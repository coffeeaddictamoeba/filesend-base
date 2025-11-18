#include "../include/key_utils.h"
#include <fcntl.h>
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int load_key(const char* key_path, unsigned char* key, size_t key_len) {
    int fd;
    fd = open(key_path, O_RDONLY);
    if (fd < 0) {
        perror(RED "open key file (read)" RESET);
        return -1;
    }
        
    ssize_t n = read(fd, key, key_len);
    close(fd);

    if (n != (ssize_t)key_len) {
        fputs(RED "[ERROR] Key file size mismatch\n" RESET, stderr);
        return -1;
    }

    return 0;
}

int create_key(const char* key_path, unsigned char* key, size_t key_len) {
    int fd;
    fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror(RED "open key file (create)" RESET);
        return -1;
    }

    randombytes_buf(key, key_len);

    ssize_t n = write(fd, key, key_len);
    if (n != (ssize_t)key_len) {
        perror(RED "write key" RESET);
        close(fd);
        return -1;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        perror(RED "fchmod" RESET);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int load_or_create_key(const char* key_path, unsigned char* key, size_t key_len) {
    struct stat st;
    return (stat(key_path, &st) == 0) ? load_key(key_path, key, key_len) : create_key(key_path, key, key_len);
}