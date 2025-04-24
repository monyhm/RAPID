#include "client_robo.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define BUFFER_SIZE 1024

/* Global variables */
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static int sock = -1;
static int i2c_fd = -1;
int executed_spin_ninety = 0;
int executed_spin_oneeighty = 0;
int executed_rest = 0;

/* SSL context configuration */
static void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

/* I2C Setup */
static int setup_i2c() {
    int fd = open(I2C_DEVICE, O_RDWR);
    if (fd < 0) return -1;
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Initialize communication */
void comm_init(const char *hostname, int port) {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(hostname)
    };
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, sock);
    
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    i2c_fd = setup_i2c();
    config_servo();
}

/* Cleanup resources */
void comm_cleanup() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sock != -1) close(sock);
    if (ctx) SSL_CTX_free(ctx);
    if (i2c_fd != -1) close(i2c_fd);
}

/* Send hash to server */
int comm_send_hash(const char *hash, int is_initial) {
    char msg[BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "HASH:%s:%s", is_initial ? "INIT" : "PERIODIC", hash);
    SSL_write(ssl, msg, strlen(msg));

    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
    if (bytes <= 0) return -1;
    buffer[bytes] = '\0';

    return strncmp(buffer, "HASH_OK", 7) == 0 ? 0 : -1;
}

void comm_send_ticket_request() {
    SSL_write(ssl, "TICKET\n", 7);
    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
    if (bytes > 0 && i2c_fd != -1) {
        write(i2c_fd, buffer, bytes);
    }
}

/* Simplified command sender (no hashing here) */
int comm_send_command(const char *command) {
    if (SSL_write(ssl, command, strlen(command)) <= 0) {
        return -1;
    }

    if (strcmp(command, "spin ninety") == 0) {
        spin_ninety();
    } else if (strcmp(command, "spin oneeighty") == 0) {
        spin_oneeighty();
    } else if (strcmp(command, "rest") == 0) {
        rest();
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return -1;
    }

    char ack[BUFFER_SIZE];
    int bytes = SSL_read(ssl, ack, BUFFER_SIZE-1);
    if (bytes <= 0 || strncmp(ack, "COMMAND_ACK", 11) != 0) {
        return -1;
    }

    return 0;
}

/* Servo control functions (now with built-in hashing) */
void spin_ninety() {
    softPwmWrite(BASE_SERVO_PIN, 15);
    printf("Executed: spin ninety\n");
    delay(1000);
    executed_spin_ninety = 1;

    // Dynamic hash update
    char *current_hash = calculate_program_hash();
    if (current_hash) {
        comm_send_hash(current_hash, 0); // 0 = periodic hash
        free(current_hash);
    }
}

void spin_oneeighty() {
    softPwmWrite(BASE_SERVO_PIN, 25);
    printf("Executed: spin oneeighty\n");
    delay(1000);
    executed_spin_oneeighty = 1;

    // Dynamic hash update
    char *current_hash = calculate_program_hash();
    if (current_hash) {
        comm_send_hash(current_hash, 0);
        free(current_hash);
    }
}

void rest() {
    softPwmWrite(BASE_SERVO_PIN, 0);
    printf("Executed: rest position\n");
    delay(1000);
    executed_rest = 1;

    // Dynamic hash update
    char *current_hash = calculate_program_hash();
    if (current_hash) {
        comm_send_hash(current_hash, 0);
        free(current_hash);
    }
}

/* Servo initialization */
void config_servo() {
    if (wiringPiSetupGpio() == -1) {
        fprintf(stderr, "Failed to initialize WiringPi\n");
        exit(EXIT_FAILURE);
    }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    softPwmCreate(BASE_SERVO_PIN, 0, 200);
    printf("Servo initialized\n");
}

/* Hash calculation functions (unchanged) */
unsigned char* compute_sha256(const unsigned char* data, size_t data_len, unsigned int* hash_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char* hash = malloc(EVP_MD_size(md));
    if (!hash) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }
    *hash_len = EVP_MD_size(md);

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, hash, hash_len);
    EVP_MD_CTX_free(mdctx);

    return hash;
}

unsigned char *get_opcode(void *func_ptr, size_t length) {
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((long)func_ptr & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        return NULL;
    }

    unsigned char *buffer = malloc(length);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }
    memcpy(buffer, func_ptr, length);
    return buffer;
}

char *calculate_program_hash() {
    size_t opcode_length = 28;
    unsigned char *current_hash = NULL;
    unsigned int hash_length = 0;

    void (*functions[3])(void);
    int num_functions = 0;

    if (executed_spin_ninety)  functions[num_functions++] = spin_ninety;
    if (executed_spin_oneeighty) functions[num_functions++] = spin_oneeighty;
    if (executed_rest) functions[num_functions++] = rest;

    if (num_functions == 0) {
        functions[num_functions++] = spin_ninety;
        functions[num_functions++] = spin_oneeighty;
    }

    for (int i = 0; i < num_functions; i++) {
        unsigned char *opcode = get_opcode((void *)functions[i], opcode_length);
        if (!opcode) {
            fprintf(stderr, "Failed to retrieve opcode for function %d\n", i);
            return NULL;
        }

        if (i == 0) {
            current_hash = compute_sha256(opcode, opcode_length, &hash_length);
        } else {
            unsigned char *combined = malloc(hash_length + opcode_length);
            memcpy(combined, current_hash, hash_length);
            memcpy(combined + hash_length, opcode, opcode_length);
            free(current_hash);
            
            current_hash = compute_sha256(combined, hash_length + opcode_length, &hash_length);
            free(combined);
        }
        free(opcode);
    }

    char *hash_str = malloc(hash_length * 2 + 1);
    for (size_t i = 0; i < hash_length; i++) {
        sprintf(&hash_str[i*2], "%02x", current_hash[i]);
    }
    hash_str[hash_length * 2] = '\0';
    free(current_hash);

    return hash_str;
}

/* Hardcoded sequence (Method 2) */
void execute_sequence(const char *server_ip) {
    comm_init(server_ip, PORT);

    // Send initial hash
    char *initial_hash = calculate_program_hash();
    if (initial_hash) {
        printf("Initial hash: %s\n", initial_hash);
        if (comm_send_hash(initial_hash, 1) != 0) {
            fprintf(stderr, "Initial hash verification failed\n");
            free(initial_hash);
            comm_cleanup();
            exit(EXIT_FAILURE);
        }
        free(initial_hash);
    }

    // Predefined sequence
    comm_send_command("spin ninety");
    delay(500);
    comm_send_command("spin oneeighty");
    delay(500);
    comm_send_command("rest");

    comm_cleanup();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    execute_sequence(argv[1]);
    return EXIT_SUCCESS;
}
