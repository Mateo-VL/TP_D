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
        return 1;
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
        return 1;
    }

    if (connect(s, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("connect");
        close(s);
        freeaddrinfo(servinfo);
        return 1;
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


long ms_ahora(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* La respuesta es CODE|ACTION|TEXT|SIGNATURE. Es valida si SIGNATURE ==
 * md5(CODE|ACTION|TEXT|SECRET). Las respuestas de error (400/401) traen 32
 * ceros porque el servidor no puede firmarlas: esas se aceptan. */
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
 * Los datagramas con firma invalida se descartan en silencio y se sigue
 * esperando el tiempo restante.
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

    /* En UDP connect() no envia nada: solo fija el destino por defecto y hace
     * que recv() ignore datagramas de otros origenes */
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




int main(){
    char* username = "grupo14";
    char* secret = "lqrB6Xv9";
    char serverip[16] = "167.114.129.206";
    char* port = "20262";

    uint8_t digest[16];
    char resultado[100];/*<username><PIPE><ip_address><PIPE><secret>*/


    char ip_address[16];


    if (obtener_IP(ip_address, sizeof(ip_address)) == -1) return 1;
    printf("IP publica: %s\n", ip_address);

    snprintf(resultado, sizeof(resultado), "%s%s%s%s%s", username,"|", ip_address,"|", secret);
    printf("strlen = %zu\nresultado: %s\n",strlen(resultado), resultado);

    md5((const uint8_t *)resultado, strlen(resultado), digest);

    char signature[33];
    for (int i = 0; i < 16; i++) {
        sprintf(signature + i * 2,"%02x", digest[i]);
    }
    printf("signature: %s\n", signature);

    char PDU[256];
    char reply[256];

    snprintf(PDU, sizeof(PDU), "%s%s%s%s%s", username,"|", ip_address,"|", signature);
    printf("strlen = %zu\nPDU: %s\n",strlen(PDU), PDU);

    int rc = udp_pedir(serverip, port, PDU, secret, reply, sizeof(reply), 10000);
    if (rc == -2) { fprintf(stderr, "timeout: sin respuesta valida en 10 s\n"); return 1; }
    if (rc == -1) return 1;
    printf("respuesta: %s\n", reply);


    return 0;
}