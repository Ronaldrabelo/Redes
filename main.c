#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#define BUFFER_SIZE 4096
#define RETRY_COUNT 3
#define TIMEOUT_SEC 5

#pragma pack(1)
// Message type codes
#define ITR_CODE 1  // Individual Token Request
#define ITR_RESP_CODE 2  // Individual Token Response
#define ITV_CODE 3  // Individual Token Validation
#define ITV_RESP_CODE 4  // Individual Token Status
#define GTR_CODE 5  // Group Token Request
#define GTR_RESP_CODE 6  // Group Token Response
#define GTV_CODE 7  // Group Token Validation
#define GTV_RESP_CODE 8  // Group Token Status
#define ERROR_CODE 256  // Error Message

// Error codes
#define INVALID_MESSAGE_CODE 1
#define INCORRECT_MESSAGE_LENGTH 2
#define INVALID_PARAMETER 3
#define INVALID_SINGLE_TOKEN 4
#define ASCII_DECODE_ERROR 5

// Basic message structures
struct IndividualTokenRequest {
    uint16_t type;
    char id[12];
    uint32_t nonce;
};

struct IndividualTokenResponse {
    uint16_t type;
    char id[12];
    uint32_t nonce;
    char token[64];
};

struct IndividualTokenValidation {
    uint16_t type;
    char id[12];
    uint32_t nonce;
    char token[64];
};

struct IndividualTokenStatus {
    uint16_t type;
    char id[12];
    uint32_t nonce;
    char token[64];
    uint8_t status;
};

struct ErrorMessage {
    uint16_t type;
    uint16_t error_code;
};

// SAS structure (80 bytes)
struct SAS {
    char id[12];
    uint32_t nonce;
    char token[64];
};

// Buffer for dynamic message allocation
unsigned char message_buffer[BUFFER_SIZE];

// Parse SAS from string format "id:nonce:token"
int parse_sas(const char *sas_str, struct SAS *sas) {
    char id[13] = {0};
    char token[65] = {0};
    unsigned int nonce;

    if (sscanf(sas_str, "%12[^:]:%u:%64s", id, &nonce, token) != 3) {
        fprintf(stderr, "Error parsing SAS: %s\n", sas_str);
        return -1;
    }

    // Validate token (should be hex characters only)
    for (int i = 0; i < strlen(token); i++) {
        if (!isxdigit(token[i])) {
            fprintf(stderr, "Error: Token contains non-hex characters\n");
            return -1;
        }
    }

    // Fill in the SAS structure
    memset(sas->id, ' ', 12);
    strncpy(sas->id, id, strlen(id));
    sas->nonce = nonce;
    memcpy(sas->token, token, 64);

    return 0;
}

// Format SAS to string "id:nonce:token"
void format_sas(const struct SAS *sas, char *sas_str) {
    char id[13] = {0};
    strncpy(id, sas->id, 12);
    char *end = id + 12;
    while (end > id && *(end-1) == ' ') end--;
    *end = '\0';

    sprintf(sas_str, "%s:%u:%.64s", id, sas->nonce, sas->token);
}

// Format GAS to string "sas1+sas2+...+sasN+token"
void format_gas(uint16_t count, const struct SAS *sas_array, const char *group_token, char *gas_str) {
    gas_str[0] = '\0';
    char sas_str[100];

    for (int i = 0; i < count; i++) {
        format_sas(&sas_array[i], sas_str);
        strcat(gas_str, sas_str);
        if (i < count - 1) {
            strcat(gas_str, "+");
        }
    }

    strcat(gas_str, "+");
    strcat(gas_str, group_token);
}

// Parse GAS from string format "sas1+sas2+...+sasN+token"
int parse_gas(const char *gas_str, uint16_t *count, struct SAS **sas_array, char *group_token) {
    // Count the number of '+' to determine the number of SAS
    int plus_count = 0;
    for (int i = 0; gas_str[i]; i++) {
        if (gas_str[i] == '+') plus_count++;
    }

    if (plus_count < 1) {
        fprintf(stderr, "Error: Invalid GAS format\n");
        return -1;
    }

    *count = plus_count;
    *sas_array = (struct SAS *)malloc((*count) * sizeof(struct SAS));
    if (!(*sas_array)) {
        perror("Error allocating memory for SAS array");
        return -1;
    }

    char *gas_copy = strdup(gas_str);
    if (!gas_copy) {
        perror("Error duplicating gas_str");
        free(*sas_array);
        return -1;
    }

    char *token = strtok(gas_copy, "+");
    for (int i = 0; i < *count; i++) {
        if (!token) {
            fprintf(stderr, "Error: Not enough SAS in GAS\n");
            free(gas_copy);
            free(*sas_array);
            return -1;
        }

        if (parse_sas(token, &(*sas_array)[i]) != 0) {
            free(gas_copy);
            free(*sas_array);
            return -1;
        }

        // Network byte order conversion
        (*sas_array)[i].nonce = htonl((*sas_array)[i].nonce);

        token = strtok(NULL, "+");
    }

    // The last token should be the group token
    if (!token || strlen(token) != 64) {
        fprintf(stderr, "Error: Invalid group token\n");
        free(gas_copy);
        free(*sas_array);
        return -1;
    }

    strcpy(group_token, token);
    free(gas_copy);

    return 0;
}

// Create a socket and resolve the address
int create_socket_and_resolve(const char *host, int port, struct sockaddr_storage *addr, socklen_t *addr_len) {
    struct addrinfo hints, *res, *p;
    int sockfd;
    char port_str[6];

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    // Try to create socket with available addresses
    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        // Set timeout
        struct timeval tv;
        tv.tv_sec = TIMEOUT_SEC;
        tv.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("Error setting timeout");
            close(sockfd);
            freeaddrinfo(res);
            return -1;
        }

        // Success
        memcpy(addr, p->ai_addr, p->ai_addrlen);
        *addr_len = p->ai_addrlen;
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        fprintf(stderr, "Failed to create socket\n");
        return -1;
    }

    return sockfd;
}

// Send Individual Token Request
int send_itr(const char *host, int port, const char *id, uint32_t nonce) {
    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int sockfd, retry_count = 0;
    struct IndividualTokenRequest request;
    struct IndividualTokenResponse response;

    sockfd = create_socket_and_resolve(host, port, &server_addr, &addr_len);
    if (sockfd < 0) return -1;

    // Prepare request
    request.type = htons(ITR_CODE);
    memset(request.id, ' ', 12);
    strncpy(request.id, id, strlen(id));
    request.nonce = htonl(nonce);

    while (retry_count < RETRY_COUNT) {
        // Send request
        if (sendto(sockfd, &request, sizeof(request), 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("sendto failed");
            close(sockfd);
            return -1;
        }

        // Receive response
        ssize_t recvlen = recvfrom(sockfd, &response, sizeof(response), 0, NULL, NULL);
        if (recvlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout, retrying...\n");
                retry_count++;
                continue;
            }
            perror("recvfrom failed");
            close(sockfd);
            return -1;
        }

        // Check response
        uint16_t resp_type = ntohs(response.type);
        if (resp_type == ITR_RESP_CODE) {
            // Success
            struct SAS sas;
            memcpy(sas.id, response.id, 12);
            sas.nonce = ntohl(response.nonce);
            memcpy(sas.token, response.token, 64);

            // Print SAS in the standard format
            char sas_str[100];
            format_sas(&sas, sas_str);
            printf("%s\n", sas_str);
            close(sockfd);
            return 0;
        } else if (resp_type == ERROR_CODE) {
            struct ErrorMessage *error = (struct ErrorMessage *)&response;
            fprintf(stderr, "Server returned error code: %d\n", ntohs(error->error_code));
            close(sockfd);
            return -1;
        } else {
            fprintf(stderr, "Unexpected response type: %d\n", resp_type);
            close(sockfd);
            return -1;
        }
    }

    fprintf(stderr, "Max retries reached, giving up.\n");
    close(sockfd);
    return -1;
}

// Send Individual Token Validation
int send_itv(const char *host, int port, const char *sas_str) {
    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int sockfd, retry_count = 0;
    struct IndividualTokenValidation request;
    struct IndividualTokenStatus response;
    struct SAS sas;

    // Parse SAS
    if (parse_sas(sas_str, &sas) != 0) {
        return -1;
    }

    sockfd = create_socket_and_resolve(host, port, &server_addr, &addr_len);
    if (sockfd < 0) return -1;

    // Prepare request
    request.type = htons(ITV_CODE);
    memcpy(request.id, sas.id, 12);
    request.nonce = htonl(sas.nonce);
    memcpy(request.token, sas.token, 64);

    while (retry_count < RETRY_COUNT) {
        // Send request
        if (sendto(sockfd, &request, sizeof(request), 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("sendto failed");
            close(sockfd);
            return -1;
        }

        // Receive response
        ssize_t recvlen = recvfrom(sockfd, &response, sizeof(response), 0, NULL, NULL);
        if (recvlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout, retrying...\n");
                retry_count++;
                continue;
            }
            perror("recvfrom failed");
            close(sockfd);
            return -1;
        }

        // Check response
        uint16_t resp_type = ntohs(response.type);
        if (resp_type == ITV_RESP_CODE) {
            // Print status
            printf("%d\n", response.status);
            close(sockfd);
            return 0;
        } else if (resp_type == ERROR_CODE) {
            struct ErrorMessage *error = (struct ErrorMessage *)&response;
            fprintf(stderr, "Server returned error code: %d\n", ntohs(error->error_code));
            close(sockfd);
            return -1;
        } else {
            fprintf(stderr, "Unexpected response type: %d\n", resp_type);
            close(sockfd);
            return -1;
        }
    }

    fprintf(stderr, "Max retries reached, giving up.\n");
    close(sockfd);
    return -1;
}

// Send Group Token Request
int send_gtr(const char *host, int port, uint16_t count, char *sas_strs[]) {
    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int sockfd, retry_count = 0;

    if (count < 1 || count > 15) {
        fprintf(stderr, "Error: Invalid SAS count (must be 1-15)\n");
        return -1;
    }

    // Parse all SAS
    struct SAS *sas_array = (struct SAS *)malloc(count * sizeof(struct SAS));
    if (!sas_array) {
        perror("Failed to allocate memory for SAS array");
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (parse_sas(sas_strs[i], &sas_array[i]) != 0) {
            free(sas_array);
            return -1;
        }
    }

    // Create socket
    sockfd = create_socket_and_resolve(host, port, &server_addr, &addr_len);
    if (sockfd < 0) {
        free(sas_array);
        return -1;
    }

    // Prepare the request message
    size_t msg_size = 4 + (count * 80);  // 2 bytes type + 2 bytes count + count * 80 bytes SAS
    unsigned char *msg = (unsigned char *)malloc(msg_size);
    if (!msg) {
        perror("Failed to allocate memory for message");
        free(sas_array);
        close(sockfd);
        return -1;
    }

    // Set message type (5 for GTR)
    *(uint16_t *)msg = htons(GTR_CODE);
    // Set SAS count
    *(uint16_t *)(msg + 2) = htons(count);

    // Copy each SAS to the message
    for (int i = 0; i < count; i++) {
        memcpy(msg + 4 + (i * 80), sas_array[i].id, 12);
        *(uint32_t *)(msg + 4 + (i * 80) + 12) = htonl(sas_array[i].nonce);
        memcpy(msg + 4 + (i * 80) + 16, sas_array[i].token, 64);
    }

    // Allocate buffer for response
    size_t resp_size = 4 + (count * 80) + 64;  // 2 bytes type + 2 bytes count + count * 80 bytes SAS + 64 bytes token
    unsigned char *resp = (unsigned char *)malloc(resp_size);
    if (!resp) {
        perror("Failed to allocate memory for response");
        free(msg);
        free(sas_array);
        close(sockfd);
        return -1;
    }

    while (retry_count < RETRY_COUNT) {
        // Send request
        if (sendto(sockfd, msg, msg_size, 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("sendto failed");
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }

        // Receive response
        ssize_t recvlen = recvfrom(sockfd, resp, resp_size, 0, NULL, NULL);
        if (recvlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout, retrying...\n");
                retry_count++;
                continue;
            }
            perror("recvfrom failed");
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }

        // Check response
        uint16_t resp_type = ntohs(*(uint16_t *)resp);
        if (resp_type == GTR_RESP_CODE) {
            // Get SAS count from response
            uint16_t resp_count = ntohs(*(uint16_t *)(resp + 2));
            if (resp_count != count) {
                fprintf(stderr, "Error: Response SAS count doesn't match request\n");
                free(resp);
                free(msg);
                free(sas_array);
                close(sockfd);
                return -1;
            }

            // Extract and format the group token
            char group_token[65];
            memcpy(group_token, resp + 4 + (count * 80), 64);
            group_token[64] = '\0';

            // Extract the SAS structures
            for (int i = 0; i < count; i++) {
                memcpy(sas_array[i].id, resp + 4 + (i * 80), 12);
                sas_array[i].nonce = ntohl(*(uint32_t *)(resp + 4 + (i * 80) + 12));
                memcpy(sas_array[i].token, resp + 4 + (i * 80) + 16, 64);
            }

            // Format and print the GAS
            char gas_str[1024];
            format_gas(count, sas_array, group_token, gas_str);
            printf("%s\n", gas_str);

            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return 0;
        } else if (resp_type == ERROR_CODE) {
            fprintf(stderr, "Server returned error code: %d\n", ntohs(*(uint16_t *)(resp + 2)));
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        } else {
            fprintf(stderr, "Unexpected response type: %d\n", resp_type);
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }
    }

    fprintf(stderr, "Max retries reached, giving up.\n");
    free(resp);
    free(msg);
    free(sas_array);
    close(sockfd);
    return -1;
}

// Send Group Token Validation
int send_gtv(const char *host, int port, const char *gas_str) {
    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int sockfd, retry_count = 0;
    uint16_t count;
    struct SAS *sas_array;
    char group_token[65];

    // Parse GAS
    if (parse_gas(gas_str, &count, &sas_array, group_token) != 0) {
        return -1;
    }

    // Create socket
    sockfd = create_socket_and_resolve(host, port, &server_addr, &addr_len);
    if (sockfd < 0) {
        free(sas_array);
        return -1;
    }

    // Prepare the request message
    size_t msg_size = 4 + (count * 80) + 64;  // 2 bytes type + 2 bytes count + count * 80 bytes SAS + 64 bytes token
    unsigned char *msg = (unsigned char *)malloc(msg_size);
    if (!msg) {
        perror("Failed to allocate memory for message");
        free(sas_array);
        close(sockfd);
        return -1;
    }

    // Set message type (7 for GTV)
    *(uint16_t *)msg = htons(GTV_CODE);
    // Set SAS count
    *(uint16_t *)(msg + 2) = htons(count);

    // Copy each SAS to the message
    for (int i = 0; i < count; i++) {
        memcpy(msg + 4 + (i * 80), sas_array[i].id, 12);
        *(uint32_t *)(msg + 4 + (i * 80) + 12) = sas_array[i].nonce;  // Already in network byte order from parse_gas
        memcpy(msg + 4 + (i * 80) + 16, sas_array[i].token, 64);
    }

    // Copy the group token
    memcpy(msg + 4 + (count * 80), group_token, 64);

    // Allocate buffer for response
    size_t resp_size = 4 + (count * 80) + 64 + 1;  // 2 bytes type + 2 bytes count + count * 80 bytes SAS + 64 bytes token + 1 byte status
    unsigned char *resp = (unsigned char *)malloc(resp_size);
    if (!resp) {
        perror("Failed to allocate memory for response");
        free(msg);
        free(sas_array);
        close(sockfd);
        return -1;
    }

    while (retry_count < RETRY_COUNT) {
        // Send request
        if (sendto(sockfd, msg, msg_size, 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("sendto failed");
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }

        // Receive response
        ssize_t recvlen = recvfrom(sockfd, resp, resp_size, 0, NULL, NULL);
        if (recvlen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout, retrying...\n");
                retry_count++;
                continue;
            }
            perror("recvfrom failed");
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }

        // Check response
        uint16_t resp_type = ntohs(*(uint16_t *)resp);
        if (resp_type == GTV_RESP_CODE) {
            // Print status (the last byte of the response)
            printf("%d\n", resp[resp_size - 1]);

            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return 0;
        } else if (resp_type == ERROR_CODE) {
            fprintf(stderr, "Server returned error code: %d\n", ntohs(*(uint16_t *)(resp + 2)));
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        } else {
            fprintf(stderr, "Unexpected response type: %d\n", resp_type);
            free(resp);
            free(msg);
            free(sas_array);
            close(sockfd);
            return -1;
        }
    }

    fprintf(stderr, "Max retries reached, giving up.\n");
    free(resp);
    free(msg);
    free(sas_array);
    close(sockfd);
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <host> <port> <command> [args...]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  itr <id> <nonce>\n");
        fprintf(stderr, "  itv <SAS>\n");
        fprintf(stderr, "  gtr <N> <SAS-1> <SAS-2> ... <SAS-N>\n");
        fprintf(stderr, "  gtv <GAS>\n");
        return EXIT_FAILURE;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *command = argv[3];

    if (strcmp(command, "itr") == 0) {
        if (argc != 6) {
            fprintf(stderr, "Usage: %s <host> <port> itr <id> <nonce>\n", argv[0]);
            return EXIT_FAILURE;
        }
        const char *id = argv[4];
        uint32_t nonce = atoi(argv[5]);
        return send_itr(host, port, id, nonce);
    } else if (strcmp(command, "itv") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s <host> <port> itv <SAS>\n", argv[0]);
            return EXIT_FAILURE;
        }
        const char *sas_str = argv[4];
        return send_itv(host, port, sas_str);
    } else if (strcmp(command, "gtr") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: %s <host> <port> gtr <N> <SAS-1> <SAS-2> ... <SAS-N>\n", argv[0]);
            return EXIT_FAILURE;
        }
        uint16_t count = atoi(argv[4]);
        if (count < 1 || count > 15 || argc != 5 + count) {
            fprintf(stderr, "Error: Invalid SAS count or arguments\n");
            return EXIT_FAILURE;
        }
        return send_gtr(host, port, count, &argv[5]);
    } else if (strcmp(command, "gtv") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s <host> <port> gtv <GAS>\n", argv[0]);
            return EXIT_FAILURE;
        }
        const char *gas_str = argv[4];
        return send_gtv(host, port, gas_str);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}