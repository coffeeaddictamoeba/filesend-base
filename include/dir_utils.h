#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <string.h>

#include "../include/file_utils.h"

typedef struct processed_node {
    char *name;
    struct processed_node *next;
} processed_node_t;

typedef struct {
    CURL *curl;
    key_mode_config_t *cf;

#ifdef USE_WS
    const char **ws_files;
    int ws_count;
    int ws_cap;
#endif

} send_ctx_t;

typedef struct {
    key_mode_config_t *cf;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
} sym_ctx_t;

typedef struct {
    key_mode_config_t *cf;
    unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
    unsigned char pr_key[crypto_box_SECRETKEYBYTES]; // only used for decrypt
    int is_decrypt; // 0 = encrypt, 1 = decrypt
} asym_ctx_t;

// Callback signature for processing a single file
typedef int (*file_cb_t)(const char* file_path, void* ctx);

int monitor_path(const char* p, int timeout_secs, file_cb_t cb, void* ctx);

int send_file_callback(const char* file_path, void* ctx_void);
int sym_file_callback(const char* file_path, void* ctx_void);
int asym_file_callback(const char* file_path, void* ctx_void);

#ifdef USE_WS
int ws_queue_add_file(send_ctx_t* ctx, const char* file_path);
void ws_queue_free(send_ctx_t* ctx);
#endif

