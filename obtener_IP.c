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

int main(int argc, char *argv[])
{
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
    printf("IP de %s: %s\n", host, ipstr); /*Simplemente para ver el host*/

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

    const char *req = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n";
    if (send(s, req, strlen(req), 0) == -1) { perror("send"); close(s); return -1; }

    /* Acumulamos TODA la respuesta antes de parsear */
    char resp[2048];


    size_t total = 0; /*Total del mensaje recibido*/
    ssize_t n; /*tamaño del fragmento recibido*/
    while (total < sizeof(resp) - 1 && /**/
           (n = recv(s, resp + total, sizeof(resp) - 1 - total, 0)) > 0) {
        total += n;
    }
    close(s);
    resp[total] = '\0';



    /* El body empieza despues de la linea vacia */
    char *body = strstr(resp, "\r\n\r\n");
    if (body == NULL) { fprintf(stderr, "respuesta HTTP invalida\n"); return -1; }
    body += 4;

    /* Sacamos espacios / saltos de linea al final */
    size_t len = strlen(body);
    while (len > 0 && (body[len-1] == '\n' || body[len-1] == '\r' || body[len-1] == ' '))
        body[--len] = '\0';

    if (len == 0 || len >= 16) { fprintf(stderr, "IP invalida\n"); return -1; }
    printf("IP publica: %s\n", body);
    return 0;
}

