#include <stddef.h>
#include <stdint.h>

#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "ui_utils.h"
#include "key_utils.h"

#define CHUNK_SIZE  4096

typedef struct {
    int on_all;
    char* init_file;
    char* dest_file;
    char* mode;
    char* key_mode;
    char* sym_key_path;      // symmetric
    char* private_key_path;  // asymmetric
    char* public_key_path ;  // asymmetric
    char* url;
    char* cert_path;
} key_mode_config_t;

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint32_t pmode;
} file_metadata_t;

int sign_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len);
int verify_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len);
int decrypt_file_symmetric(const unsigned char* key, const char* enc_path, const char* dec_path);
int encrypt_file_symmetric(const unsigned char* key, const char* plain_path, const char* enc_path);
int encrypt_file_asymmetric(const unsigned char* pub_key, const char* plain_path, const char* enc_path, int enc_all);
int decrypt_file_asymmetric(const unsigned char* pub_key, const unsigned char* pr_key, const char* enc_path, const char* dec_path, int dec_all);
