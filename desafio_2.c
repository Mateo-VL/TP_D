/* Conexion TCP, usamos getaddrinfo para configurar el socket */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>   /* inet_ntop() */
#include <netdb.h>
#include <time.h>
#include <poll.h>
#include <stdlib.h>
#include <stdint.h>
#include "md5.h"


int obtener_IP(char* ip, size_t size_ip){
    int s; /* file descriptor del socket */
    struct addrinfo hints;
    struct addrinfo *servinfo; /* es donde van los resultados */

    int status; /*codigo de error de getadrrinfo*/

    char ipstr[INET_ADDRSTRLEN]; /*Donde vamos a guardar el ip*/

    const char *host = "api.ipify.org"; /*De donde sacamos el ip*/

    memset(&hints,0,sizeof(hints));     /* es necesario inicializar con ceros */
    hints.ai_family = AF_INET;          /* Address Family */
    hints.ai_socktype = SOCK_STREAM;    /* Socket Type */

    /*Sacamos la información*/
    if ((status = getaddrinfo(host, "80", &hints, &servinfo)) != 0) {
        fprintf(stderr, "Error en getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    /* Convertir la direccion a texto */
    struct sockaddr_in *addr = (struct sockaddr_in *)servinfo->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ipstr, sizeof(ipstr));
    /*printf("IP de %s: %s\n", host, ipstr); Simplemente para ver el host*/

    /*Creamos socket*/
    s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (s == -1) {
        perror("socket");
        freeaddrinfo(servinfo);
        return -1;
    }

    if (connect(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("connect");
        close(s);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);

    const char *req = "GET / HTTP/1.0\r\n"
                        "Host: api.ipify.org\r\n\r\n";
    if (send(s, req, strlen(req), 0) == -1) {
        perror("send");
        close(s);
        return -1;
    }

    /* Acumulamos TODA la respuesta antes de parsear */
    char resp[2048];


    size_t total = 0; /*Total del mensaje recibido*/
    ssize_t n; /*tamaño del fragmento recibido*/
    while (total < sizeof(resp) - 1 && /*Nos aseguramos que no se llene el buffer, con -1 para guardar espacio para el \0*/
    /*Argumentos de recv: [s] el socket | [resp + total] es donde escribir lo recibido | [sizeof(resp) - 1 - total] cuanto puedo escribir como maximo | [0] sin flags*/
            (n = recv(s, resp + total, sizeof(resp) - 1 - total, 0)) > 0) { /*recv devuele n el tamaño del fragmento recibido, 0 si se cerro la conexion y -1 si hay error. >0 continua el bucle hasta que se cierre la conexion o haya error*/
        total += n; /*Sumo lo recibido al total*/
    }
    close(s); /*cierro el socket*/
    resp[total] = '\0';/*Agrego \0 al final*/



    /* El body empieza despues de la linea vacia */
    char *body = strstr(resp, "\r\n\r\n"); /*Me quedo con lo que hay despues de \r\n\r\n*/
    if (body == NULL) { fprintf(stderr, "respuesta HTTP invalida\n"); return -1; } /*Chequeo que llego bien*/
    body += 4; /*Elimino os vacios para quedarme con la informacion*/

    /* Sacamos espacios / saltos de linea al final */
    size_t len = strlen(body);
    while (len > 0 && (body[len-1] == '\n' || body[len-1] == '\r' || body[len-1] == ' '))
        body[--len] = '\0';

    if (len == 0 || len >= size_ip) { fprintf(stderr, "IP invalida\n"); return -1; }
    /*printf("IP publica: %s\n", body);*/

    strcpy(ip, body);

    return 0;
}

void md5_a_hex(const char *s, char out[33])
{
    uint8_t d[16];
    md5((const uint8_t *)s, strlen(s), d);
    for (int i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", d[i]);
    out[32] = '\0';
}

/*Para tener la hora a agregar al PDU*/
long ms_ahora(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* La respuesta es CODE|ACTION|TEXT|SIGNATURE. Es valida si SIGNATURE == md5(CODE|ACTION|TEXT|SECRET). Las respuestas de error (400/401) traen 32 ceros porque el servidor no puede firmarlas: esas se aceptan. */
int respuesta_valida(const char *msg, const char *secret)
{
    const char *ultimo = strrchr(msg, '|');
    if (ultimo == NULL || strlen(ultimo + 1) != 32)
        return 0;
    if (strcmp(ultimo + 1, "00000000000000000000000000000000") == 0)
        return 1;

    char a_firmar[512], esperado[33];
    int n = snprintf(a_firmar, sizeof(a_firmar), "%.*s|%s",
                        (int)(ultimo - msg), msg, secret);
    if (n < 0 || (size_t)n >= sizeof(a_firmar))
        return 0;
    md5_a_hex(a_firmar, esperado);
    return strcmp(esperado, ultimo + 1) == 0;
}

/* Envia msg por UDP y espera hasta timeout_ms por una respuesta valida.
 * Los datagramas con firma invalida se descartan en silencio y se sigue esperando el tiempo restante.
 * Devuelve 0 (respuesta en reply), -1 error, -2 timeout. */

int udp_pedir(const char *server, const char *port, const char *msg,
              const char *secret, char *reply, size_t reply_size, int timeout_ms)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(server, port, &hints, &servinfo);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    int s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (s == -1) {
        perror("socket");
        freeaddrinfo(servinfo);
        return -1;
    }

    /* En UDP connect() no envia nada: solo fija el destino por defecto y hace que recv() ignore datagramas de otros origenes */
    if (connect(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("connect");
        close(s);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);

    if (send(s, msg, strlen(msg), 0) == -1) {   /* 1 send = 1 datagrama */
        perror("send");
        close(s);
        return -1;
    }

    long limite = ms_ahora() + timeout_ms;
    for (;;) {
        long restante = limite - ms_ahora();
        if (restante <= 0) { close(s); return -2; }

        struct pollfd pfd = { .fd = s, .events = POLLIN };
        int r = poll(&pfd, 1, (int)restante);
        if (r == -1) {
            if (errno == EINTR) continue;
            perror("poll"); close(s); return -1;
        }
        if (r == 0) { close(s); return -2; }

        ssize_t n = recv(s, reply, reply_size - 1, 0);
        if (n == -1) { perror("recv"); close(s); return -1; }
        reply[n] = '\0';

        if (respuesta_valida(reply, secret)) {
            close(s);
            return 0;
        }
        /* firma invalida: descartar en silencio y seguir esperando */
    }
}





/* el cliente se conecta por TCP al puerto dinamico, recibe PDUs delimitadas por CR LF (con framing), las parsea y reenvia por UDP,firmadas, al servidor de la catedra.*/

#define RX_BUF_SIZE        4096   /* buffer de recepcion TCP (>> 122 B)      */
#define TS_MAX_LEN         11     /* largo maximo del timestamp              */
#define MSG_MAX_LEN        100    /* largo maximo del mensaje                */
#define TS_MAX_EDAD        300    /* segundos de tolerancia del timestamp    */
#define TCP_RECV_TIMEOUT   15000  /* ms sin datos antes de abandonar         */
#define TX_BUF_SIZE        (RX_BUF_SIZE + 512)

/* md5 hex en minuscula de un buffer cualquiera (usa longitud, no strlen) */
void md5_hex_buf(const uint8_t *data, size_t len, char out[33])
{
    uint8_t d[16];
    md5(data, len, d);
    for (int i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", d[i]);
    out[32] = '\0';
}

/* Parser de PDU 
 * p/len: PDU SIN el CR LF final. Devuelve el PARSE_CODE.
 *
 * Orden de validacion (si hay varios errores a la vez, gana el primero):
 *   400 si no hay exactamente un '&' (no son 2 campos)
 *   timestamp: 405 (caracter invalido o vacio) -> 407 (>11) -> 406 (vencido)
 *   mensaje:   409 (vacio) -> 408 (caracter invalido) -> 410 (>100)
 *   200 si todo esta bien
 */
int parsear_pdu(const unsigned char *p, size_t len, time_t ahora)
{
    /*recorre la PDU contando los &. Guardo en pos_amp la posición del primero*/
    size_t n_amp = 0, pos_amp = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == '&') {
            if (n_amp == 0) pos_amp = i;
            n_amp++;
        }
    }
    if (n_amp != 1)/*Si hay 0 o mas de 1 retorno error*/
        return 400;

    /*El timestamp empieza en p y mide pos_amp caracteres. El mensaje empieza justo después del & y mide lo que queda.*/
    const unsigned char *ts  = p;
    size_t ts_len            = pos_amp;
    const unsigned char *msg = p + pos_amp + 1;
    size_t msg_len           = len - pos_amp - 1;

    /*validación del timestamp. Si esta vacio, si esta mal el formato*/
    if (ts_len == 0)
        return 405;
    for (size_t i = 0; i < ts_len; i++)
        if (ts[i] < '0' || ts[i] > '9')
            return 405;
    if (ts_len > TS_MAX_LEN)
        return 407;

    /*Convierto el texto a número a mano, */
    long long t = 0;
    for (size_t i = 0; i < ts_len; i++)
        t = t * 10 + (ts[i] - '0');
    long long dif = (long long)ahora - t;
    if (dif < 0) dif = -dif;
    if (dif > TS_MAX_EDAD)
        return 406;

    /* Validación del mensaje */
    if (msg_len == 0)
        return 409;
    for (size_t i = 0; i < msg_len; i++)
        if (msg[i] < 0x20 || msg[i] > 0x7D || msg[i] == '&' || msg[i] == '|')
            return 408;
    if (msg_len > MSG_MAX_LEN)
        return 410;

    return 200;
}

/*Contexto y estadisticas */
/*Agrupa lo que necesita manejar_pdu para no pasar 8 parámetros*/
typedef struct {
    const char *username;
    const char *secret;
    int udp_fd;            /* socket UDP ya "conectado" al servidor */
    int incluir_crlf;      /* 1: la PDU viaja con CR LF en el datagrama UDP  IMPORTANTE REVISAR Y ELIMINAR ESTO UNA VEZ SEPAMOS*/
    /* estadisticas */
    int pdus_totales;
    int pdus_enviadas;
    int pdus_con_pipe;     /* no se reenvian (contienen 0x7C) */
    int pdus_descartadas;  /* resincronizacion por desborde de buffer */
} ctx_t;

/*Es el buffer de recepción: data guarda los bytes, len cuántos hay ocupados, y descartando es un
flag que uso solo en el caso raro de desborde (más abajo).*/
typedef struct {
    unsigned char data[RX_BUF_SIZE];
    size_t len;
    int descartando;       /* 1: estamos tirando bytes hasta el proximo CR LF */
} rxbuf_t;

/* Imprime bytes de forma segura (escapa lo no imprimible) */
static void imprimir_seguro(const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (p[i] >= 0x20 && p[i] < 0x7F) putchar(p[i]);
        else printf("\\x%02x", p[i]);
    }
}

/* Copia 'n' bytes a buf en la posicion *off, verificando el limite. Evita pisar la memoria si no entra en la capacidad cap */
static int agregar(unsigned char *buf, size_t cap, size_t *off,
                   const void *src, size_t n)
{
    if (*off + n > cap) return -1;
    memcpy(buf + *off, src, n);
    *off += n;
    return 0;
}

/* Parsea una PDU completa (sin CR LF) y, si corresponde, la reenvia por UDP con formato  USERNAME|PDU|PARSE_CODE|SIGNATURE  */
static void manejar_pdu(ctx_t *c, const unsigned char *pdu, size_t len)
{
    c->pdus_totales++; /*Cuenta la PDU y la parsea con la hora actual (time(NULL))*/
    int code = parsear_pdu(pdu, len, time(NULL));

    printf("PDU #%d [%zu B] code=%d : \"", c->pdus_totales, len, code);
    imprimir_seguro(pdu, len);/*Muestra en pantalla lo que se parseó*/
    printf("\"");

    if (memchr(pdu, '|', len) != NULL) {/*busca |. Si está, cuento y salgo.*/
        printf("  -> NO se reenvia (contiene 0x7C)\n");
        c->pdus_con_pipe++;
        return;
    }

    char code_str[8];
    snprintf(code_str, sizeof(code_str), "%d", code);/*Convierto el código numérico a texto ("200")*/

    /* Armamos el cuerpo firmado:  USERNAME|PDU|CODE   (y luego |SECRET) */
    /*Voy concatenando USERNAME|PDU[\r\n]|CODE. Cada agregar devuelve 0 o -1, y con |= acumulo en err si alguno falló. Al final reviso una sola vez. El \r\n solo se agrega si incluir_crlf está activo (lo que controla el flag --sin-crlf).*/
    unsigned char cuerpo[TX_BUF_SIZE];
    size_t off = 0;
    int err = 0;
    err |= agregar(cuerpo, sizeof(cuerpo), &off, c->username, strlen(c->username));
    err |= agregar(cuerpo, sizeof(cuerpo), &off, "|", 1);
    err |= agregar(cuerpo, sizeof(cuerpo), &off, pdu, len);
    if (c->incluir_crlf)
        err |= agregar(cuerpo, sizeof(cuerpo), &off, "\r\n", 2);
    err |= agregar(cuerpo, sizeof(cuerpo), &off, "|", 1);
    err |= agregar(cuerpo, sizeof(cuerpo), &off, code_str, strlen(code_str));
    if (err) { printf("  -> error: PDU demasiado grande\n"); return; }

    /* firma = md5(cuerpo | SECRET) */
    /* firma es md5(USERNAME|PDU|CODE|SECRET). Eso es el cuerpo, más |, más el secret. El secreto se usa solo para calcular el MD5 y nunca viaja en el datagrama.*/
    unsigned char a_firmar[TX_BUF_SIZE + 128];
    size_t off_f = 0;
    err |= agregar(a_firmar, sizeof(a_firmar), &off_f, cuerpo, off);
    err |= agregar(a_firmar, sizeof(a_firmar), &off_f, "|", 1);
    err |= agregar(a_firmar, sizeof(a_firmar), &off_f, c->secret, strlen(c->secret));
    char firma[33];
    md5_hex_buf(a_firmar, off_f, firma);

    /* Datagrama final y envío   datagrama = cuerpo | FIRMA */
    unsigned char datagrama[TX_BUF_SIZE + 64];
    size_t off_d = 0;
    err |= agregar(datagrama, sizeof(datagrama), &off_d, cuerpo, off);
    err |= agregar(datagrama, sizeof(datagrama), &off_d, "|", 1);
    err |= agregar(datagrama, sizeof(datagrama), &off_d, firma, 32);
    if (err) { printf("  -> error armando datagrama\n"); return; }

    if (send(c->udp_fd, datagrama, off_d, 0) == -1) {
        printf("\n");
        perror("send UDP");
        return;
    }
    c->pdus_enviadas++;
    printf("  -> enviada por UDP\n");
}

/* busco CR LF. devuelve el indice del CR, o -1 si no esta */
static long buscar_crlf(const unsigned char *b, size_t len)
{
    for (size_t i = 0; i + 1 < len; i++)
        if (b[i] == '\r' && b[i + 1] == '\n')
            return (long)i;
    return -1;
}

/* FRAMING: extrae del buffer todas las PDUs completas (terminadas en CR LF), las procesa, y deja al inicio del buffer el resto (PDU parcial).
 * Cubre: PDU partida en varios segmentos, varias PDUs en un segmento y la cobminacion de ambos casos. */
static void procesar_buffer(ctx_t *c, rxbuf_t *rx)
{
    long idx;
    while ((idx = buscar_crlf(rx->data, rx->len)) >= 0) {
        if (rx->descartando) {
            rx->descartando = 0;       /* fin del tramo basura */
            c->pdus_descartadas++;
            printf("(descartado tramo sin delimitador, resincronizado)\n");
        } else {
            manejar_pdu(c, rx->data, (size_t)idx);
        }
        size_t consumido = (size_t)idx + 2;
        memmove(rx->data, rx->data + consumido, rx->len - consumido);
        rx->len -= consumido;
    }

    /* Buffer lleno sin CR LF: no es una PDU valida (max 122 B). Tiramos todoy seguimos descartando hasta el proximo CR LF; conservamos el ultimo byte por si era el CR. */
    if (rx->len == RX_BUF_SIZE) {
        rx->descartando = 1;
        rx->data[0] = rx->data[rx->len - 1];
        rx->len = 1;
    }
}

/* trae el puerto de "200|Port|<puerto>|<firma>" y devulve 0 si ok */
static int extraer_puerto(const char *reply, char *port, size_t port_size)
{
    if (strncmp(reply, "200|Port|", 9) != 0)
        return -1;
    const char *ini = reply + 9;
    const char *fin = strchr(ini, '|');
    if (fin == NULL || fin == ini || (size_t)(fin - ini) >= port_size)
        return -1;
    memcpy(port, ini, (size_t)(fin - ini));
    port[fin - ini] = '\0';

    char *resto;
    long v = strtol(port, &resto, 10);
    if (*resto != '\0' || v < 1 || v > 65535)
        return -1;
    return 0;
}

/* Socket TCP conectado a server:port  
 * devuelve fd o -1 */
static int conectar_tcp(const char *server, const char *port)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(server, port, &hints, &servinfo);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }
    int s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (s == -1) {
        perror("socket");
        freeaddrinfo(servinfo);
        return -1;
    }
    if (connect(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("connect");
        close(s);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);
    return s;
}

/* Socket UDP "conectado" al servidor (para poder usar send)*/
static int abrir_udp(const char *server, const char *port)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(server, port, &hints, &servinfo);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }
    int s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (s == -1) {
        perror("socket");
        freeaddrinfo(servinfo);
        return -1;
    }
    if (connect(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("connect");
        close(s);
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);
    return s;
}

/*  conecta, recibe, delimita, parsea y reenvia */
int desafio2(const char *server, const char *udp_port, const char *tcp_port,
             const char *username, const char *secret, int incluir_crlf)
{
    int tcp = conectar_tcp(server, tcp_port);
    if (tcp == -1) return -1;

    int udp = abrir_udp(server, udp_port);
    if (udp == -1) { close(tcp); return -1; }

    ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.username = username;
    ctx.secret = secret;
    ctx.udp_fd = udp;
    ctx.incluir_crlf = incluir_crlf;

    rxbuf_t rx;
    memset(&rx, 0, sizeof(rx));

    printf("Conectado por TCP a %s:%s, esperando PDUs...\n", server, tcp_port);

    for (;;) {
        struct pollfd pfd = { .fd = tcp, .events = POLLIN };
        int r = poll(&pfd, 1, TCP_RECV_TIMEOUT);
        if (r == -1) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (r == 0) {
            fprintf(stderr, "timeout: %d ms sin datos por TCP\n", TCP_RECV_TIMEOUT);
            break;
        }

        ssize_t n = recv(tcp, rx.data + rx.len, RX_BUF_SIZE - rx.len, 0);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }
        if (n == 0)
            break;  /* el servidor cerro la conexion */

        rx.len += (size_t)n;
        procesar_buffer(&ctx, &rx);
    }
    close(tcp);

    if (rx.len > 0 && !rx.descartando) {
        printf("Quedaron %zu bytes sin CR LF (PDU incompleta, se descarta): \"", rx.len);
        imprimir_seguro(rx.data, rx.len);
        printf("\"\n");
    }

    close(udp);
    printf("\n--- Resumen ---\n"
           "PDUs delimitadas:            %d\n"
           "Reenviadas por UDP:          %d\n"
           "No reenviadas (contienen |): %d\n"
           "Tramos descartados:          %d\n",
           ctx.pdus_totales, ctx.pdus_enviadas, ctx.pdus_con_pipe,
           ctx.pdus_descartadas);
    return 0;
}

/*   Uso:  ./desafio_2 [--sin-crlf]: en el datagrama UDP la PDU va SIN el CR LF final (por defecto va CON CR LF, ya que el enunciado incluyeel END_DELIMITER dentro de la definicion de PDU).
 *
 * Para pruebas locales (no usar en la entrega real) se pueden pisar:
 *   TP_SERVER_IP   IP del servidor (por defecto la de la catedra)
 *   TP_PUBLIC_IP   IP publica a informar (evita consultar api.ipify.org)
 */
int main(int argc, char **argv)
{
    const char *username = "grupo14";
    const char *secret = "lqrB6Xv9";
    const char *serverip = "167.114.129.206";
    const char *port = "20262";
    int incluir_crlf = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sin-crlf") == 0) incluir_crlf = 0;
        else { fprintf(stderr, "uso: %s [--sin-crlf]\n", argv[0]); return 1; }
    }

    const char *env;
    if ((env = getenv("TP_SERVER_IP")) != NULL) serverip = env;

    /* del Desafio 1  */
    char ip_address[16];
    if ((env = getenv("TP_PUBLIC_IP")) != NULL && strlen(env) < sizeof(ip_address)) {
        strcpy(ip_address, env);
    } else if (obtener_IP(ip_address, sizeof(ip_address)) == -1) {
        return 1;
    }
    printf("IP publica: %s\n", ip_address);

    char a_firmar[128], signature[33], PDU[256], reply[256];
    snprintf(a_firmar, sizeof(a_firmar), "%s|%s|%s", username, ip_address, secret);
    md5_a_hex(a_firmar, signature);
    snprintf(PDU, sizeof(PDU), "%s|%s|%s", username, ip_address, signature);
    printf("Pedido: %s\n", PDU);

    int rc = udp_pedir(serverip, port, PDU, secret, reply, sizeof(reply), 10000);
    if (rc == -2) { fprintf(stderr, "timeout: sin respuesta valida en 10 s\n"); return 1; }
    if (rc == -1) return 1;
    printf("respuesta: %s\n", reply);

    char tcp_port[8];
    if (extraer_puerto(reply, tcp_port, sizeof(tcp_port)) == -1) {
        fprintf(stderr, "el servidor no concedio un puerto (respuesta no exitosa)\n");
        return 1;
    }


    if (desafio2(serverip, port, tcp_port, username, secret, incluir_crlf) == -1)
        return 1;

    return 0;
}
