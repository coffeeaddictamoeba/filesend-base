#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "defaults.h"
#include "key_utils.h"

#define CHUNK_SIZE  4096

#define ENC_FLAG_ENABLED    (1u << 0)
#define ENC_FLAG_SYMMETRIC  (1u << 1)
#define ENC_FLAG_ALL        (1u << 2)
#define ENC_FLAG_RESERVED1  (1u << 3)
#define ENC_FLAG_RESERVED2  (1u << 4)

typedef struct {
    char* mode;          // "send" / "encrypt" / "decrypt"
    char* init_path;     // file or directory
    char* dest_path;     // for encrypt/decrypt (file or dir)

    char* url;           // send mode

    char* key_path;
    char* dec_key_path;
    char* cert_path;
    
    int   use_ws;        // 0 = use https, >0 = use websocket

    int  retry_enabled;   // 0 = no retry, 1 = allow retry
    int  max_retries;     // how many attempts per file (total)
    int  timeout_secs;  // 0 = no monitoring, >0 = watch dir

    uint32_t flags;      // |Res|Res|All|Sym|Enc|
} filesend_config_t;

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint32_t pmode;
} file_metadata_t;

int make_readonly(const char *path);

// Integrity check
int compute_file_sha256(const char *path, unsigned char out[crypto_hash_sha256_BYTES]);
int compute_file_sha256_hex(const char *path, char *hex_out, size_t hex_out_len);

// Encryption/decryption
int encrypt_file_symmetric(
    const unsigned char* key, 
    const char* plain_path, 
    const char* enc_path,
    int enc_all
);

int decrypt_file_symmetric(
    const unsigned char* key, 
    const char* enc_path, 
    const char* dec_path,
    int dec_all
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
