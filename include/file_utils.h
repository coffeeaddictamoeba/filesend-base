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

int exec_on_file(
    const char* file_path,
    const char* exec_s
);

#endif // FILE_UTILS_H
