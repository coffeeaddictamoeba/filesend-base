#include <stddef.h>
#include <stdint.h>

#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "ui_utils.h"

#define CHUNK_SIZE  4096

int sign_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len);
int verify_file(const unsigned char* key, const char* file, const char* mac_file, unsigned char* mac, size_t mac_len);
int decrypt_file(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* enc_path, const char* dec_path);
int encrypt_file(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], const char* plain_path, const char* enc_path);
