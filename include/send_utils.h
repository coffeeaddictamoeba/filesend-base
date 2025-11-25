#include <curl/curl.h>

#define SEND_CHUNK_SIZE 65536

typedef struct {
    FILE* fp;
    const char** files;
    int file_count;
    int current_file;
    char device_id[64];
    int phase;  // 0=send header, 1=send data, 2=send file_end, 3=wait reply
} client_state_t;

int send_file_via_https(CURL *curl, const char* url, const char* enc_path, const char* cert);
int send_encrypted_file_via_https(CURL *curl, const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all);
int send_end_signal_via_https(CURL *curl, const char *url, const char *cert);

#ifdef USE_WS
    int send_files_via_ws(const char *ws_url, const char *device_id, const char **files, int file_count, const char* cert);
    int send_encrypted_files_via_ws(const char* ws_url, const char* file_path, const char* key_path, const char* key_mode, const char* cert, int enc_all);
#endif