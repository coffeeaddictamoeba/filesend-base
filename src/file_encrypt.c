#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sodium.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "../include/key_utils.h"

#define RESET   "\033[0m"
#define RED     "\033[31m"      // Errors
#define YELLOW  "\033[33m"      // Warnings
#define GREEN   "\033[32m"      // Success

#define CHUNK_SIZE  4096

int encrypt_file(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* plain_path, const char* enc_path) {
    FILE* fin = fopen(plain_path, "rb");
    if (!fin) {
        perror(RED "fopen plain_path in file encrypt" RESET);
        return -1;
    }

    char tmp_enc_path[1024];
    snprintf(tmp_enc_path, sizeof(tmp_enc_path), "%s.tmp", enc_path);

    FILE* fout = fopen(tmp_enc_path, "wb");
    if (!fout) {
        perror(RED "fopen enc_path in file encrypt" RESET);
        fclose(fin);
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key) != 0) {
        fputs(
            RED "[ERROR] crypto_secretstream_xchacha20poly1305_init_push failed\n" RESET,
            stderr
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (fwrite(header, 1, sizeof(header), fout) != sizeof(header)) {
        fputs(
            RED "[ERROR] Failed to write header\n" RESET,
            stderr
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t n;
    int is_last;

    for (;;) {
        n = fread(inbuf, 1, CHUNK_SIZE, fin);
        is_last = feof(fin);

        unsigned char tag = is_last 
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL 
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long out_len = 0;

        if(crypto_secretstream_xchacha20poly1305_push(&st, outbuf, &out_len, inbuf, n, NULL, 0, tag) != 0) {
            fputs(
                RED "[ERROR] secretstream_push failed\n" RESET,
                stderr
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fputs(
                RED "[ERROR] Failed to write encrypted chunk\n" RESET,
                stderr
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (is_last) break;
    }

    fclose(fin);
    fclose(fout);

    if (rename(tmp_enc_path, enc_path) != 0) {
        perror(RED "rename" RESET);
        return -1;
    }

    printf(GREEN "[SUCCESS] File %s was successfully encrypted\n" RESET, enc_path);

    return 0;
}

int decrypt_file(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* enc_path, const char* dec_path) {
    FILE* fin = fopen(enc_path, "rb");
    if (!fin) {
        perror(RED "fopen of enc_path in decrypt file" RESET);
        return -1;
    }

    char tmp_dec_path[1024];
    snprintf(tmp_dec_path, sizeof(tmp_dec_path), "%s.tmp", dec_path);
    
    FILE* fout = fopen(tmp_dec_path, "wb");
    if (!fout) {
        perror(RED "fopen of dec_path in decrypt file" RESET);
        fclose(fin);
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (fread(header, 1, sizeof(header), fin) != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        if (feof(fin)) {
            fputs(RED "[ERROR] Encrypted file is too short\n" RESET, stderr);
        } else {
            perror(RED "fread of header in decrypt file" RESET);
        }
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        fputs(
            RED "[ERROR] crypto_secretstream_xchacha20poly1305_init_pull failed\n" RESET,
            stderr
        );
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char inbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char outbuf[CHUNK_SIZE];
    size_t n;
    int is_last;

    for(;;) {
        n = fread(inbuf, 1, CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES, fin);
        is_last = feof(fin);

        unsigned char tag = is_last 
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL 
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long out_len = 0;

        if (crypto_secretstream_xchacha20poly1305_pull(&st, outbuf, &out_len, &tag, inbuf, n, NULL, 0) != 0) {
            fputs(
                RED "[ERROR] secretstream_pull failed\n" RESET,
                stderr
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (fwrite(outbuf, 1, out_len, fout) != out_len) {
            fputs(
                RED "[ERROR] Failed to write encrypted chunk\n" RESET,
                stderr 
            );
            fclose(fin);
            fclose(fout);
            return -1;
        }

        if (is_last) break;
    }

    fclose(fin);
    fclose(fout);

    if (rename(tmp_dec_path, dec_path) != 0) {
        perror("rename");
        return -1;
    }

    printf(GREEN "[SUCCESS] File %s was successfully decrypted\n" RESET, dec_path);

    return 0;
}

void usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s encrypt <file>\n"
        "  %s decrypt <file>\n",
        prog, prog);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char* mode = argv[1];
    const char* file = argv[2];

    if (sodium_init() < 0) {
        fputs(
            RED "[ERROR] sodium_init failed\n" RESET, 
            stderr
        );
        return EXIT_FAILURE;
    }

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (load_or_create_key(KEY_DIR, key, sizeof(key)) != 0) {
        fputs(
            RED "[ERROR] Failed to write encrypted chunk\n" RESET,
            stderr
        );
        return EXIT_FAILURE;
    }

    if (strcmp(mode, "encrypt") == 0) {
        return encrypt_file(key, file, file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    } else if (strcmp(mode, "decrypt") == 0) {
        return decrypt_file(key, file, file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}