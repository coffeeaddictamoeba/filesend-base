#include <curl/curl.h>

int send_file(const char* url, const char* enc_path, const char* cert);
int send_encrypted_file(const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all);
