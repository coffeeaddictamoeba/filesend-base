#include "../include/key_utils.h"
#include <fcntl.h>
#include <sodium.h>
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
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
        fprintf(
            stderr, 
            RED "[ERROR] Key file size mismatch\n" RESET
        );
        return -1;
    }

    return 0;
}

int save_key(const char* key_path, unsigned char* key, size_t key_len) {
    int fd;
    fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror(RED "open key file (create)" RESET);
        return -1;
    }

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

int create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len) {
    randombytes_buf(key, key_len);

    if (save_key(key_path, key, key_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] save_key failed\n" RESET
        );
        return -1;
    }

    return 0;
}

int load_or_create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len) {
    struct stat st;
    return (stat(key_path, &st) == 0) 
        ? load_key(key_path, key, key_len) 
        : create_symmetric_key(key_path, key, key_len);
}

int load_or_create_asymmetric_key_pair(const char* pub_key_path, unsigned char* pub_key, size_t pub_key_len) {
    struct stat pub_st;
    struct stat pr_st;
    return (stat(pub_key_path, &pub_st) == 0) || (stat(PR_KEY_DIR, &pr_st) == 0) 
        ? load_key(pub_key_path, pub_key, pub_key_len) 
        : create_asymmetric_key_pair(pub_key_path, PR_KEY_DIR, pub_key, pub_key_len);
}

int create_asymmetric_key_pair(const char* pub_key_path, const char* pr_key_path, unsigned char* pub_key, size_t pub_key_len) {
    unsigned char pr_key[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pub_key, pr_key);

    FILE *fpk = fopen(pub_key_path, "wb");
    FILE *fsk = fopen(pr_key_path, "wb");
    if (!fpk || !fsk) {
        perror(RED "open key file (create asymmetric key pair)" RESET);
        return -1;
    }

    fwrite(pub_key, 1, pub_key_len, fpk);
    fwrite(pr_key, 1, sizeof(pr_key), fsk);

    fclose(fpk);
    fclose(fsk);

    return 0;
}

int create_sealed_key(unsigned char* file_key, size_t file_key_len, unsigned char* pub_key, unsigned char* sealed_key, size_t sealed_key_len, const char* sealed_key_path) {
    randombytes_buf(file_key, file_key_len);
    if (crypto_box_seal(sealed_key, file_key, file_key_len, pub_key) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_box_seal failed\n" RESET
        );
        return -1;
    }

    if (save_key(sealed_key_path, sealed_key, sealed_key_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] save_key failed\n" RESET
        );
        return -1;
    }

    return 0;
}
