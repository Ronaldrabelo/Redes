#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "2804:1f4a:dcc:ff03::1"
#define SERVER_PORT 51001
#define BUFFER_SIZE 1024

struct IndividualTokenRequest {
    uint16_t type;
    char id[12];
    uint32_t nonce;
} __attribute__((packed));

struct IndividualTokenResponse {
    uint16_t type;
    char id[12];
    uint32_t nonce;
    char token[64];
} __attribute__((packed));

void send_individual_token_request(const char *id, uint32_t nonce) {
    int sock;
    struct sockaddr_in6 server_addr;
    struct IndividualTokenRequest request;
    struct IndividualTokenResponse response;
    socklen_t addr_len = sizeof(server_addr);

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(SERVER_PORT);
    inet_pton(AF_INET6, SERVER_IP, &server_addr.sin6_addr);

    request.type = htons(1);
    memset(request.id, ' ', 12);
    strncpy(request.id, id, strlen(id));
    request.nonce = htonl(nonce);

    if (sendto(sock, &request, sizeof(request), 0, (struct sockaddr *)&server_addr, addr_len) < 0) {
        perror("Erro ao enviar mensagem");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Requisicao enviada para %s:%d\n", SERVER_IP, SERVER_PORT);

    if (recvfrom(sock, &response, sizeof(response), 0, (struct sockaddr *)&server_addr, &addr_len) < 0) {
        perror("Erro ao receber resposta");
        close(sock);
        exit(EXIT_FAILURE);
    }

    response.type = ntohs(response.type);
    response.nonce = ntohl(response.nonce);

    if (response.type == 2) {
        printf("Token Recebido:\n");
        printf("ID: %.12s\n", response.id);
        printf("Nonce: %u\n", response.nonce);
        printf("Token: %.64s\n", response.token);
    } else {
        printf("Resposta inesperada do servidor.\n");
    }
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <id> <nonce>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *id = argv[1];
    uint32_t nonce = atoi(argv[2]);

    if (strlen(id) > 12) {
        printf("Erro: ID deve ter no máximo 12 caracteres.\n");
        return EXIT_FAILURE;
    }
    send_individual_token_request(id, nonce);
    return EXIT_SUCCESS;
}
