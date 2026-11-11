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




int main(){
    char* username = "grupo14";
    char* secret = "lqrB6Xv9";
    /*char SERVERIP[16] = "167.114.129.206";
    int SERVER_PORT = 20262;*/

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

    char PDU[100];

    snprintf(PDU, sizeof(PDU), "%s%s%s%s%s", username,"|", ip_address,"|", signature);
    printf("strlen = %zu\nPDU: %s\n",strlen(PDU), PDU);

    return 0;
}