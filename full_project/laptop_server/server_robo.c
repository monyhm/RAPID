#include "server_robo.h"

static SSL_CTX *ctx = NULL;
static SOCKET server_socket = INVALID_SOCKET;
//static const char *expected_initial_hash = "8e47becb54f7dc0cc93f42f83cde96662a63755b7eb287450003345a8e1c49cf"; // Replace with your expected hash
//static const char *expected_periodic_hash = "35f7bf8a86a3a86608f24c4c857df3da6d9f1273f4ed931f0b9b3005a473f2d7"; // Replace with your expected hash
static const char *expected_initial_hash = "4d691dab2087800ec17d29df5dbe3dddd092a241a54e4d0ca66228d2e67a30e5"; // Replace with your expected hash
static const char *expected_periodic_hash = "caecb2e1df7c1fce6054caa201a4b1ddfbb8f6f7996a1a15706c827c1000904c";
/* Initialize Windows sockets */
void server_init() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        exit(1);
    }

    if (init_server_ssl() != 0) {
        fprintf(stderr, "SSL initialization failed\n");
        exit(1);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        exit(1);
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        exit(1);
    }

    printf("Server listening on port %d...\n", PORT);
}

/* Cleanup resources */
void server_cleanup() {
    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    WSACleanup();
}

/* Create SSL context */
SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

/* Configure SSL context */
void configure_server_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "../certs/cert.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "../certs/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Verify client certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL);
}

/* Initialize SSL */
int init_server_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_server_context();
    configure_server_context(ctx);

    return 0;
}

/* Handle client connection */
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (1) {
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            int err = SSL_get_error(ssl, bytes_received);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                printf("Client disconnected\n");
            } else {
                fprintf(stderr, "SSL read error: %d\n", err);
            }
            break;
        }

        buffer[bytes_received] = '\0';
        printf("Received: %s\n", buffer);

        if (strncmp(buffer, "HASH:", 5) == 0) {
            /* Parse hash message */
            char *hash_type = strtok(buffer + 5, ":");
            char *received_hash = strtok(NULL, ":");
            
            if (hash_type && received_hash) {
                if (verify_client_hash(received_hash, hash_type) == 0) {
                    SSL_write(ssl, "HASH_OK\n", 8);
                } else {
                    SSL_write(ssl, "HASH_INVALID\n", 13);
                    break;
                }
            }
        } 
        else if (strncmp(buffer, "TICKET", 6) == 0) {
            SSL_write(ssl, "TICKET_ACK\n", 11);
        }
        else {
            /* Process movement commands */
            process_client_command(buffer);
            SSL_write(ssl, "COMMAND_ACK\n", 12);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/* Verify client hash */
int verify_client_hash(const char *received_hash, const char *hash_type) {
    const char *expected_hash = NULL;
    
    if (strcmp(hash_type, "INIT") == 0) {
        expected_hash = expected_initial_hash;
    } else if (strcmp(hash_type, "PERIODIC") == 0) {
        expected_hash = expected_periodic_hash;
    } else {
        return -1;
    }

    printf("Verifying %s hash:\nReceived: %s\nExpected: %s\n", 
           hash_type, received_hash, expected_hash);

    return strcmp(received_hash, expected_hash);
}

/* Process client commands */
void process_client_command(const char *command) {
    printf("Processing command: %s\n", command);
    
    // Here you could add any server-side logic for the commands
    // Since the actual movement happens on the client, this is just for logging/verification
    if (strcmp(command, "spin ninety") == 0) {
        printf("Client requested: Spin 90 degrees\n");
    } 
    else if (strcmp(command, "spin oneeighty") == 0) {
        printf("Client requested: Spin 180 degrees\n");
    } 
    else if (strcmp(command, "rest") == 0) {
        printf("Client requested: Rest position\n");
    } 
    else {
        printf("Unknown command received: %s\n", command);
    }
}

/* Main server loop */
int main() {
    server_init();

    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
            continue;
        }

        printf("Client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            closesocket(client_socket);
            SSL_free(ssl);
            continue;
        }

        handle_client(ssl);
        closesocket(client_socket);
    }

    server_cleanup();
    return 0;
}