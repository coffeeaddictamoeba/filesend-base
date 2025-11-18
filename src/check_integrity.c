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

#include <sodium/core.h>
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include "../include/key_utils.h"

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint32_t pmode;
} file_metadata_t;

int hash_file_contents(crypto_generichash_state* state, const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror(RED "fopen" RESET);
        return -1;
    }

    unsigned char buf[4096];
    size_t n;
    while((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (crypto_generichash_update(state, buf, (unsigned long long)n) != 0) {
            fputs(
                RED "[ERROR] crypto_generichash_update failed\n" RESET, 
                stderr
            );
            fclose(f);
            return -1;
        }
    }

    if (ferror(f)) {
        perror(RED "fread" RESET);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int get_metadata(const char* path, file_metadata_t* fmd) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror(RED "stat" RESET);
        return -1;
    }

    fmd->size = (uint64_t)st.st_size;
    fmd->mtime = (uint64_t)st.st_mtime;
    fmd->pmode = (uint32_t)st.st_mode;

    return 0;
}

int find_file_mac(const unsigned char *key, const char* path, unsigned char* mac, size_t mac_len) {
    file_metadata_t fmd;
    if (get_metadata(path, &fmd) != 0) return -1;

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, key, sizeof(key), mac_len) != 0) {
        fputs(
            RED "[ERROR] crypto_generichash_init failed\n" RESET,
            stderr
        );
        return -1;
    }

    if (hash_file_contents(&state, path) != 0) return -1;

    if (crypto_generichash_update(&state, (const unsigned char*)&fmd, sizeof(fmd)) != 0) {
        fputs(
            RED "[ERROR] crypto_generichash_update metadata failed\n" RESET,
            stderr
        );
        return -1;
    }

    if (crypto_generichash_final(&state, mac, mac_len) != 0) {
        fputs(
            RED "[ERROR] crypto_generichash_final failed\n" RESET,
            stderr
        );
        return -1;
    }

    return 0;
}

int load_mac_hex(const char* mac_path, unsigned char* mac, size_t mac_len) {
    FILE* f = fopen(mac_path, "r");
    if (!f) {
        perror(RED "fopen MAC file"RESET);
        return -1;
    }

    char hex[1024];
    if (!fgets(hex, sizeof(hex), f)) {
        perror(RED "fgets" RESET);
        fclose(f);
        return -1;
    }

    size_t len = strcspn(hex, "\r\n");
    hex[len] = '\0';

    size_t mac_read_len = 0;
    if (sodium_hex2bin(mac, mac_len, hex, len, NULL, &mac_read_len, NULL) != 0) {
        fputs(
            RED "[ERROR] sodium_hex2bin failed\n" RESET,
            stderr
        );
        return -1;
    }

    if (mac_read_len != mac_len) {
        fprintf(
            stderr,
            RED "[ERROR] MAC length mismatch: expected %zu, got %zu\n" RESET, mac_len, mac_read_len
        );
        return -1;
    }

    return 0;
}

int save_mac_hex(const char* mac_path, const unsigned char *mac, size_t mac_len) {
    FILE* f = fopen(mac_path, "w");
    if (!f) {
        perror(RED "fopen MAC file" RESET);
        return -1;
    }

    char *hex = sodium_malloc(mac_len*2+1);
    if (!hex) {
        fputs(
            RED "[ERROR] sodium_malloc failed\n" RESET,
            stderr
        );
        return -1;
    }

    sodium_bin2hex(hex, mac_len*2+1, mac,mac_len);

    fprintf(
        f,
        "%s\n",
        hex
    );

    sodium_free(hex);
    fclose(f);

    return 0;
}

// void usage(const char* prog) {
//     fprintf(stderr,
//         "Usage:\n"
//         "  %s sign   <file> <mac_file>\n"
//         "  %s verify <file> <mac_file>\n",
//         prog, prog);
// }

int sign_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len) {
    if (find_file_mac(key, file, mac, mac_len) != 0) {
        fputs(
            RED "[ERROR] Failed to find MAC\n" RESET,
            stderr
        );
        return -1;
    }

    if (save_mac_hex(mac_file, mac, mac_len) != 0) {
        fputs(
            RED "[ERROR] Failed to save MAC hex\n" RESET,
            stderr
        );
        return -1;
    }

    printf(GREEN "[SUCCESS] MAC created and saved to %s\n" RESET, mac_file);
    return 0;
}

int verify_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len) {
    unsigned char stored_mac[crypto_generichash_BYTES];

    if (load_mac_hex(mac_file, stored_mac, sizeof(stored_mac)) != 0) {
        fputs(
            RED "[ERROR] Failed to load stored MAC\n" RESET,
            stderr
        );
        return -1;
    }

    if (find_file_mac(key, file, mac, mac_len) != 0) {
        fputs(
            RED "[ERROR] Failed to find MAC\n" RESET,
            stderr
        );
        return -1;
    }

    if (sodium_memcmp(mac, stored_mac, mac_len) == 0) {
        printf(GREEN "[SUCCESS] File contents and metadata are consistent\n" RESET);
        return 0;
    } else {
        printf(RED "[ERROR] File has been modified\n" RESET);
        return -1;
    }
}

// int main(int argc, char** argv) {
//     if (argc < 3) {
//         usage(argv[0]);
//         return EXIT_FAILURE;
//     }

//     if (sodium_init() < 0) {
//         fputs(
//             RED "[ERROR] sodium_init failed\n" RESET, 
//             stderr
//         );
//         return EXIT_FAILURE;
//     }

//     unsigned char key[crypto_generichash_KEYBYTES];

//     if (load_or_create_key(KEY_DIR, key, sizeof(key)) != 0) {
//         fprintf(
//             stderr, 
//             RED "Failed to load/create key\n" RESET
//         );
//         return EXIT_FAILURE;
//     }

//     const char* mode = argv[1];
//     const char* file = argv[2];

//     char tmp_mac_file[1024];
//     if (argc == 4) {
//         snprintf(tmp_mac_file, sizeof(tmp_mac_file), "%s", argv[3]);
//     } else {
//         snprintf(tmp_mac_file, sizeof(tmp_mac_file), "%s.mac", tmp_mac_file);
//     }

//     const char* mac_file = tmp_mac_file;

//     unsigned char mac[crypto_generichash_BYTES];

//     if (strcmp(mode, "sign") == 0) {
//         return sign_file(key, file, mac_file, mac, sizeof(mac));
//     } else if (strcmp(mode, "verify") == 0) {
//         return verify_file(key, file, mac_file, mac, sizeof(mac));
//     }
// }
