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
    fprintf(
        stderr,
        "Usage:\n"
        "  %s encrypt <file> [--symmetric|--asymmetric][--all]\n"
        "  %s decrypt <file> [--symmetric|--asymmetric][--all][--private]\n",
        prog, prog
    );
}

int parse_args(int argc, char** argv, key_mode_config_t* cf) {
    // Necessary args
    cf->mode = argv[1];
    cf->init_file = argv[2];
    cf->key_mode = argv[3];

    // Specific/optional args
    for (int i = 4; i < argc; i++) {
        const char* arg = argv[i];
        if (strcmp(arg, "--all") == 0) cf->on_all = 1;
        else if (strcmp(arg, "--private") == 0 && i+1<argc && strcmp(argv[2], "decrypt")) {
            cf->private_key_path = argv[++i];
        } else {
            fprintf(
                stderr, 
                "[ERROR] Unknown arguments\n"
            );
            return -1;
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    key_mode_config_t cf; 
    if (parse_args(argc, argv, &cf) != 0) return EXIT_FAILURE;

    if (sodium_init() < 0) {
        fprintf(
            stderr,
            RED "[ERROR] sodium_init failed\n" RESET
        );
        return EXIT_FAILURE;
    }

    // Symmetric key mode
    if (strcmp(cf.key_mode, "--symmetric") == 0) {
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(S_KEY_DIR, key, sizeof(key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create symmetric key\n" RESET
            );
            return EXIT_FAILURE;
        }

        if (strcmp(cf.mode, "encrypt") == 0) {
            return encrypt_file_symmetric(key, cf.init_file, cf.init_file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        } else if (strcmp(cf.mode, "decrypt") == 0) {
            return decrypt_file_symmetric(key, cf.init_file, cf.init_file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    } 
    
    // Asymmetric key mode (public/private key)
    else if (strcmp(cf.key_mode, "--asymmetric") == 0) {
        if (strcmp(cf.mode, "encrypt") == 0) {
            unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
            if (load_or_create_asymmetric_key_pair(PUB_KEY_DIR, pub_key, sizeof(pub_key)) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create asymmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }
            
            return encrypt_file_asymmetric(pub_key, cf.init_file, cf.init_file, cf.on_all) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
            
        } else if (strcmp(cf.mode, "decrypt") == 0) {
            unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
            unsigned char pr_key[crypto_box_SECRETKEYBYTES];

            if (load_key(PUB_KEY_DIR, pub_key, sizeof(pub_key)) != 0 || load_key(cf.private_key_path, pr_key, sizeof(pr_key)) != 0) {
                fprintf(
                    stderr, 
                    RED "Failed to load asymmetric key pair.\n" RESET
                );
                return -1;
            }

            return decrypt_file_asymmetric(pub_key, pr_key, cf.init_file, cf.init_file, cf.on_all) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    fprintf(
        stderr, 
        RED "[ERROR] Wrong arguments specified\n" RESET
    );
    return EXIT_FAILURE;
}