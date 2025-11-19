#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <sys/stat.h>

#include "../include/key_utils.h"
#include "../include/file_utils.h"

void usage(const char* prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s encrypt <file> [-sa]\n"
        "  %s decrypt <file> [-sa] --sealed <key_file>\n",
        prog, prog);
}

int main(int argc, char** argv) {
    if (argc < 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char* mode = argv[1];
    const char* file = argv[2];
    const char* key_mode = argv[3];

    if (sodium_init() < 0) {
        fputs(
            RED "[ERROR] sodium_init failed\n" RESET, 
            stderr
        );
        return EXIT_FAILURE;
    }

    // Symmetric key mode
    if (strcmp(key_mode, "-s") == 0) {
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(S_KEY_DIR, key, sizeof(key)) != 0) {
            fputs(
                RED "[ERROR] Failed to create symmetric key\n" RESET,
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
    
    // Asymmetric key mode (public/private key)
    else if (strcmp(key_mode, "-a") == 0) {
        if (strcmp(mode, "encrypt") == 0) {
            unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
            if (load_or_create_asymmetric_key_pair(PUB_KEY_DIR, pub_key, sizeof(pub_key)) != 0) {
                fputs(
                    RED "[ERROR] Failed to create asymmetric key\n" RESET,
                    stderr
                );
                return EXIT_FAILURE;
            }

            unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
            unsigned char sealed_key[crypto_box_SEALBYTES + sizeof file_key];

            char sealed_key_path[1024];
            snprintf(sealed_key_path, sizeof(sealed_key_path), "%s.sk", file);

            struct stat sealed_st;
            if (stat(sealed_key_path, &sealed_st) != 0) {
                if (create_sealed_key(file_key, sizeof(file_key), pub_key, sealed_key, sizeof(sealed_key), sealed_key_path) != 0) {
                    fputs(
                        RED "[ERROR] Failed to create sealed file key\n" RESET,
                        stderr
                    );
                    return EXIT_FAILURE;
                }
            }
            
            return encrypt_file(file_key, file, file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
            
        } else if (strcmp(mode, "decrypt") == 0) {
            unsigned char pk[crypto_box_PUBLICKEYBYTES];
            unsigned char sk[crypto_box_SECRETKEYBYTES];
            unsigned char file_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
            unsigned char sealed_key[crypto_box_SEALBYTES + sizeof file_key];

            if (load_key(PUB_KEY_DIR, pk, sizeof(pk)) != 0 || load_key(PR_KEY_DIR, sk, sizeof(sk)) != 0) {
                fprintf(
                    stderr, 
                    RED "Failed to load asymmetric key pair.\n" RESET
                );
                return -1;
            }

            const char* sealed_key_path = argv[5];
            if (load_key(sealed_key_path, sealed_key, sizeof(sealed_key)) != 0) {
                fprintf(
                    stderr, 
                    RED "Failed to load sealed key\n" RESET
                );
                return -1;
            }

            if (crypto_box_seal_open(file_key, sealed_key, sizeof sealed_key, pk, sk) != 0) {
                fprintf(
                    stderr, 
                    RED "Failed to unseal file key\n" RESET
                );
                return -1;
            }
            return decrypt_file(file_key, file, file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    else {
        fprintf(
            stderr, 
            RED "[ERROR] Wrong arguments specified\n" RESET
        );
        return EXIT_FAILURE;
    }
}