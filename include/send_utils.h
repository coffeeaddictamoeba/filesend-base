#include <curl/curl.h>

int send_file_via_https(CURL *curl, const char* url, const char* enc_path, const char* cert);
int send_encrypted_file_via_https(CURL *curl, const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all);
int send_end_signal_via_https(CURL *curl, const char *url, const char *cert);

int send_file_via_ws(const char *ws_url, const char *file_list_path);
int send_encrypted_file_via_ws(const char* ws_url, const char* file_path, const char* key_path, const char* key_mode, int enc_all);