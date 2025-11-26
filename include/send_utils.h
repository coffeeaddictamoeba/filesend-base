#ifndef SEND_UTILS_H
#define SEND_UTILS_H

#include <curl/curl.h>

extern int g_retry_enabled;
extern int g_max_retries;

inline void send_set_retry_options(int enabled, int max_retries) {
    g_retry_enabled = enabled ? 1 : 0;
    g_max_retries   = (max_retries < 1) ? 1 : max_retries;
}

int send_file_via_https(
    CURL* curl,
    const char* url,
    const char* file_path,
    const char* cert
);

int send_encrypted_file_via_https(
    CURL* curl,
    const char* url,
    const char* file_path,
    const char* cert,
    const char* key_path,
    const char* key_mode, // "symmetric" or "asymmetric"
    int enc_all
);

int send_end_signal_via_https(
    CURL *curl,
    const char *url,
    const char *cert
);

#ifdef USE_WS
#include <libwebsockets.h>

#define SEND_CHUNK_SIZE 65536

typedef struct {
    FILE* fp;
    const char** files;
    int file_count;
    int current_file;
    char device_id[64];
    int phase;  // 0=send header, 1=send data, 2=send file_end, 3=wait reply
} client_state_t;

typedef struct {
    struct lws_context *ctx;
    struct lws *wsi;

    int connected;

    char device_id[64];
    char url[256];
    char ca_path[256];

    char key_mode[16];     // "" | "symmetric" | "asymmetric"
    char key_path[256];    // path to key (if any)
    int  enc_all;          // encrypt metadata flag

    // queue of files
    char  **files;
    int     file_count;
    int     file_cap;

    // per-file status
    int *sent_ok;          // 1 if ACKed or skipped
    int *retries;          // how many attempts

    int done_flag;         // dir monitor finished, no new files
    int end_sent;          // {"type":"end"} already sent

} ws_client_t;

int  ws_client_init(
    ws_client_t *c,
    const char *ws_url,
    const char *device_id,
    const char *cert,
    const char *key_mode,
    const char *key_path,
    int enc_all
);

int  ws_client_enqueue_file(ws_client_t *c, const char *file_path);
void ws_client_mark_done(ws_client_t *c);
int  ws_client_service(ws_client_t *c, int timeout_ms);
void ws_client_destroy(ws_client_t *c);

int send_files_via_ws(
    const char* ws_url,
    const char* device_id,
    const char** files,
    int file_count,
    const char* cert  // CA file (for wss), can be NULL for ws://
);

int send_encrypted_files_via_ws(
    const char* ws_url,
    const char* device_id,
    const char** files,
    int file_count,
    const char* cert,       // CA file
    const char* key_mode,   // "symmetric" or "asymmetric"
    const char* key_path,   // path to key / pubkey
    int enc_all
);
#endif // USE_WS

#endif // SEND_UTILS_H