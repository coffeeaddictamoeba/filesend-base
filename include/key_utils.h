#include <stddef.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"      // Errors
#define YELLOW  "\033[33m"      // Warnings
#define GREEN   "\033[32m"      // Success

#define KEY_DIR "test/file_mac.key"

int load_key(const char* key_path, unsigned char* key, size_t key_len);
int create_key(const char* key_path, unsigned char* key, size_t key_len);
int load_or_create_key(const char* key_path, unsigned char* key, size_t key_len);