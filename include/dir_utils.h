#ifndef DIR_UTILS_H
#define DIR_UTILS_H

#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <string.h>

#include "file_utils.h"
#include "db_utils.h"

#ifdef USE_WS
#include "send_utils.h"
#endif

typedef struct processed_node {
    char *name;
    struct processed_node *next;
} processed_node_t;

typedef struct {
    CURL *curl;
    filesend_config_t *cf;
    db_t *sent_db;

#ifdef USE_WS
    ws_client_t *ws;
#endif

} send_ctx_t;

typedef struct {
    filesend_config_t *cf;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
} sym_ctx_t;

typedef struct {
    filesend_config_t *cf;
    unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
    unsigned char pr_key[crypto_box_SECRETKEYBYTES]; // only used for decrypt
    int is_decrypt;                                  // 0 = encrypt, 1 = decrypt
} asym_ctx_t;

// Callback signature for processing a single file
typedef int (*file_cb_t)(const char* file_path, void* ctx);

// Dir monitoring
int monitor(
    const char* p, 
    int timeout_secs, 
    file_cb_t cb, 
    void* ctx
);

// Callbacks
int send_file_callback(
    const char* file_path, 
    void* ctx_void
);

int sym_file_callback(
    const char* file_path,
    void* ctx_void
);

int asym_file_callback(
    const char* file_path,
    void* ctx_void
);

#ifdef USE_WS
typedef void (*monitor_tick_cb_t)(void *tick_ctx);

int monitor_with_tick(
    const char *p,
    int timeout_secs,
    file_cb_t cb,
    void *ctx,
    monitor_tick_cb_t tick,
    void *tick_ctx
);
#endif

#endif // DIR_UTILS_H