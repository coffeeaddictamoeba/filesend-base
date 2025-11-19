#include <stddef.h>

#include "ui_utils.h"

#define S_KEY_DIR "test/file_mac.key"
#define PUB_KEY_DIR "test/pub_key.bin"
#define PR_KEY_DIR "test/pr_key.bin"

int load_key(const char* key_path, unsigned char* key, size_t key_len);
int create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len);
int create_asymmetric_key_pair(const char* pub_key_path, const char* pr_key_path, unsigned char* pub_key, size_t pub_key_len);
int create_sealed_key(unsigned char* file_key, size_t file_key_len, unsigned char* pub_key, unsigned char* sealed_key, size_t sealed_key_len, const char* sealed_key_path);
int load_or_create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len);
int load_or_create_asymmetric_key_pair(const char* pub_key_path, unsigned char* pub_key, size_t pub_key_len);