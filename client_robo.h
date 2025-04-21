#ifndef COMM_SERVO_H
#define COMM_SERVO_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define BASE_SERVO_PIN 21
#define PORT 8443
#define BUFFER_SIZE 1024
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

/* Combined Communication and Control Functions */
void comm_init(const char *hostname, int port);
void comm_cleanup();
int comm_send_hash(const char *hash, int is_initial);
void comm_send_ticket_request();
int comm_send_command(const char *command);

/* Robotic Arm Control Functions */
void spin_ninety(void);
void spin_oneeighty(void);
void rest(void);
void config_servo(void);

/* Hash Calculation Functions */
unsigned char *compute_sha256(const unsigned char *data, size_t data_len, unsigned int *hash_len);
unsigned char *get_opcode(void *func_ptr, size_t length);
char *calculate_program_hash();

/* Utility Functions */
void print_hash(const unsigned char *hash, size_t length);
void hex_to_string(const unsigned char *hash, size_t length, char *output);

#endif // COMM_SERVO_H
