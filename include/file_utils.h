#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "ui_utils.h"
#include "key_utils.h"

#define CHUNK_SIZE  4096

typedef struct {
    char* mode;          // "send" / "encrypt" / "decrypt"
    char* init_path;     // file or directory
    char* dest_path;     // for encrypt/decrypt (file or dir)

    char* url;           // send mode

    char* key_mode;      // "symmetric" / "asymmetric" or NULL

    char* public_key_path;
    char* private_key_path;
    char* sym_key_path;
    char* cert_path;

    int   on_all;        // metadata flag
    int   timeout_secs;  // 0 = no monitoring, >0 = watch dir
    int   use_ws;        // 0 = use https, >0 = use websocket

    int  retry_enabled;   // 0 = no retry, 1 = allow retry
    int  max_retries;     // how many attempts per file (total)
} filesend_config_t;

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint32_t pmode;
} file_metadata_t;

// Integrity check
int sign_file(
    const unsigned char* key, 
    const char* file, 
    const char* mac_file, 
    unsigned char* mac, 
    size_t mac_len
);

int verify_file(
    const unsigned char* key, 
    const char* file, 
    const char* mac_file, 
    unsigned char* mac, 
    size_t mac_len
);

// Encryption/decryption
int encrypt_file_symmetric(
    const unsigned char* key, 
    const char* plain_path, 
    const char* enc_path
    /*int enc_all*/
);

int decrypt_file_symmetric(
    const unsigned char* key, 
    const char* enc_path, 
    const char* dec_path
    /*int dec_all*/
);

int encrypt_file_asymmetric(
    const unsigned char* pub_key, 
    const char* plain_path, 
    const char* enc_path, 
    int enc_all
);

int decrypt_file_asymmetric(
    const unsigned char* pub_key, 
    const unsigned char* pr_key, 
    const char* enc_path, 
    const char* dec_path, 
    int dec_all
);

#endif // FILE_UTILS_H
