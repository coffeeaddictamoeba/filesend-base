#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "../include/file_utils.h"
#include "../include/key_utils.h"
#include "../include/send_utils.h"

int g_retry_enabled = 1;
int g_max_retries   = 3;

#ifdef USE_WS
#include <libwebsockets.h>

static ws_client_t *g_ws_client = NULL;  // pointer to current client instance
client_state_t state;
#endif


int send_file_via_https(CURL* curl, const char* url, const char* file_path, const char* cert) {
    int attempts     = 0;
    int max_attempts = g_retry_enabled ? g_max_retries : 1;

    while (attempts < max_attempts) {
        attempts++;

        CURLcode res;
        int ret = 0;

        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part = curl_mime_addpart(mime);

        curl_mime_name(part, "file");
        curl_mime_filedata(part, file_path);

        curl_mimepart *dev = curl_mime_addpart(mime);
        curl_mime_name(dev, "device_id");
        curl_mime_data(dev, "pi", CURL_ZERO_TERMINATED);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // TLS options are assumed to be set once in main using cert
        if (cert != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(
                stderr,
                "[ERROR] curl_easy_perform() failed for %s (attempt %d/%d): %s\n",
                file_path, attempts, max_attempts, curl_easy_strerror(res)
            );
            ret = -1;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code == 200 || http_code == 201) {
                fprintf(
                    stderr,
                    "[SUCCESS] Server successfully received file %s\n", file_path
                );
                curl_mime_free(mime);
                return 0; // success
            } else {
                fprintf(
                    stderr,
                    "[ERROR] Server returned HTTP %ld for %s (attempt %d/%d)\n",
                    http_code, file_path, attempts, max_attempts
                );
                ret = -1;
            }
        }

        curl_mime_free(mime);

        if (ret == 0) return 0; // should not happen here
        if (attempts >= max_attempts) return -1;

        // Optional short delay before retry
        sleep(1);
    }

    return -1;
}

int send_encrypted_file_via_https(CURL* curl, const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all) {
    // Symmetric key mode
    if (strcmp(key_mode, "symmetric") == 0) {
        const char* p = (key_path == NULL) ? DEFAULT_SYM_KEY_PATH : key_path;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(p, key, sizeof(key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create symmetric key\n" RESET
            );
            return -1;
        }

        if (encrypt_file_symmetric(key, file_path, file_path) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to encrypt the file: %s (symmetric encryption)\n" RESET, file_path
            );
            return -1;
        }

        return send_file_via_https(curl, url, file_path, cert);
    }

    // Asymmetric key mode (public/private key)
    else if (strcmp(key_mode, "asymmetric") == 0) {
        const char* pub = (key_path == NULL) ? DEFAULT_PUB_KEY_PATH : key_path;
        const char* pr  = DEFAULT_SYM_KEY_PATH;  // placeholder for creation

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof(pub_key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create asymmetric key\n" RESET
            );
            return -1;
        }

        if (encrypt_file_asymmetric(pub_key, file_path, file_path, enc_all) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to encrypt the file: %s (asymmetric encryption)\n" RESET, file_path
            );
            return -1;
        }

        return send_file_via_https(curl, url, file_path, cert);
    }

    return -1; // should not reach
}

// signal server that sending ended (no more files)
int send_end_signal_via_https(CURL *curl, const char *url, const char *cert) {
    int attempts     = 0;
    int max_attempts = g_retry_enabled ? g_max_retries : 1;

    while (attempts < max_attempts) {
        attempts++;

        CURLcode res;
        int ret = 0;

        curl_mime *mime = curl_mime_init(curl);

        curl_mimepart *end = curl_mime_addpart(mime);
        curl_mime_name(end, "end");
        curl_mime_data(end, "1", CURL_ZERO_TERMINATED);

        curl_mimepart *dev = curl_mime_addpart(mime);
        curl_mime_name(dev, "device_id");
        curl_mime_data(dev, "pi", CURL_ZERO_TERMINATED);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        if (cert != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(
                stderr,
                YELLOW "[WARN] send_end_signal failed (attempt %d/%d): %s\n" RESET,
                attempts, max_attempts, curl_easy_strerror(res)
            );
            ret = -1;
        } else {
            fprintf(
                stdout,
                GREEN "[SUCCESS] Sent end-of-stream signal to server\n" RESET
            );
            curl_mime_free(mime);
            return 0;
        }

        curl_mime_free(mime);

        if (ret == 0) return 0;
        if (attempts >= max_attempts) return -1;

        // optional sleep(1);
        sleep(1);
    }

    return -1;
}

#ifdef USE_WS
int ws_ensure_status_arrays(ws_client_t *c, int new_cap) {
    int *new_ok = realloc(c->sent_ok, new_cap * sizeof(int));
    int *new_rt = realloc(c->retries, new_cap * sizeof(int));
    if (!new_ok || !new_rt) {
        fprintf(stderr, "[WS] Out of memory for status arrays\n");
        free(new_ok);
        free(new_rt);
        return -1;
    }
    // zero new portion
    for (int i = c->file_cap; i < new_cap; ++i) {
        new_ok[i] = 0;
        new_rt[i] = 0;
    }
    c->sent_ok = new_ok;
    c->retries = new_rt;
    c->file_cap = new_cap;
    return 0;
}

int ws_callback(struct lws *wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
    switch(reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_user("[WS] Connected to server\n");
            if (g_ws_client) g_ws_client->connected = 1;
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            if (state.current_file >= state.file_count) {
                if (g_ws_client && g_ws_client->done_flag && !g_ws_client->end_sent) {
                    char msg[64];
                    snprintf(msg, sizeof(msg), "{\"type\":\"end\"}");

                    size_t n = strlen(msg);
                    unsigned char *buf = malloc(LWS_PRE + n);
                    if (!buf) {
                        lwsl_err("[WS] OOM sending end\n");
                        return -1;
                    }
                    memcpy(&buf[LWS_PRE], msg, n);

                    lwsl_user("[WS] Sending end\n");
                    lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
                    free(buf);

                    g_ws_client->end_sent = 1;
                }
                return 0;
            }

            const char* path = state.files[state.current_file];
            const char* filename = strrchr(path, '/');
            if (!filename) filename = path; else filename++;

            if (state.phase == 0) {
                // send header JSON
                char json[512];
                snprintf(
                    json, sizeof(json),
                    "{\"type\":\"file\",\"filename\":\"%s\",\"device_id\":\"%s\"}",
                    filename, state.device_id
                );

                size_t n = strlen(json);
                unsigned char *buf = malloc(LWS_PRE + n);
                if (!buf) {
                    lwsl_err("[WS] OOM sending header\n");
                    return -1;
                }
                memcpy(&buf[LWS_PRE], json, n);

                lwsl_user("[WS] Sending header: %s\n", json);
                lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
                free(buf);

                // open file
                state.fp = fopen(path, "rb");
                if (!state.fp) {
                    lwsl_err("[WS] Failed to open file %s\n", path);
                    return -1;
                }

                state.phase = 1;
                lws_callback_on_writable(wsi);
                break;
            }

            if (state.phase == 1) {
                char buf_raw[SEND_CHUNK_SIZE];
                size_t r = fread(buf_raw, 1, SEND_CHUNK_SIZE, state.fp);

                if (r > 0) {
                    unsigned char *buf = malloc(LWS_PRE + r);
                    if (!buf) {
                        lwsl_err("[WS] OOM sending data\n");
                        return -1;
                    }
                    memcpy(&buf[LWS_PRE], buf_raw, r);

                    lws_write(wsi, &buf[LWS_PRE], r, LWS_WRITE_BINARY);
                    free(buf);

                    lws_callback_on_writable(wsi);
                    break;
                }

                fclose(state.fp);
                state.fp = NULL;
                state.phase = 2;
                lws_callback_on_writable(wsi);
                break;
            }

            if (state.phase == 2) {
                char json[64];
                snprintf(json, sizeof(json), "{\"type\":\"file_end\"}");

                size_t n = strlen(json);
                unsigned char *buf = malloc(LWS_PRE + n);
                if (!buf) {
                    lwsl_err("[WS] OOM sending file_end\n");
                    return -1;
                }
                memcpy(&buf[LWS_PRE], json, n);

                lwsl_user("[WS] Sending file_end for file %d\n", state.current_file);
                lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
                free(buf);

                state.phase = 3; // wait for server ack
                break;
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE:
            lwsl_user("[WS] Received reply: %.*s\n", (int)len, (char*)in);

            // server confirms file_done -> next file
            if (state.phase == 3 && g_ws_client) {
                int idx = state.current_file;
                if (idx >= 0 && idx < g_ws_client->file_count) {
                    g_ws_client->sent_ok[idx] = 1;
                }
                state.current_file++;
                state.phase = 0;
                lws_callback_on_writable(wsi);
            }
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            lwsl_err("[WS] Connection error\n");
            if (g_ws_client) g_ws_client->connected = 0;
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            lwsl_user("[WS] Connection closed\n");
            if (g_ws_client) g_ws_client->connected = 0;
            break;

        default:
            break;
    }
    return 0;
}

int ws_client_init(ws_client_t *c, const char *ws_url, const char *device_id, const char *cert, const char *key_mode, const char *key_path, int enc_all) {
    memset(c, 0, sizeof(*c));
    strncpy(c->device_id, device_id ? device_id : "pi", sizeof(c->device_id)-1);
    if (ws_url)  strncpy(c->url, ws_url, sizeof(c->url)-1);
    if (cert)    strncpy(c->ca_path, cert, sizeof(c->ca_path)-1);
    if (key_mode) strncpy(c->key_mode, key_mode, sizeof(c->key_mode)-1);
    if (key_path) strncpy(c->key_path, key_path, sizeof(c->key_path)-1);
    c->enc_all = enc_all;

    c->files    = NULL;
    c->file_cap = 0;
    c->file_count = 0;
    c->sent_ok  = NULL;
    c->retries  = NULL;

    // reset state
    memset(&state, 0, sizeof(state));
    strncpy(state.device_id, c->device_id, sizeof(state.device_id)-1);

    g_ws_client = c;

    struct lws_protocols protocols[] = {
        { "ws-protocol", ws_callback, 0, 4096 },
        { NULL, NULL, 0, 0 }
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port      = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.options  |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    if (c->ca_path[0] != '\0') {
        info.ssl_ca_filepath = c->ca_path;
    }

    c->ctx = lws_create_context(&info);
    if (!c->ctx) {
        fprintf(stderr, "[WS] Failed to create context\n");
        return -1;
    }

    // parse ws:// / wss://
    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = c->ctx;

    int use_ssl = 0;
    const char *p = NULL;

    if (strncmp(c->url, "wss://", 6) == 0) {
        use_ssl = 1;
        p = c->url + 6;
    } else if (strncmp(c->url, "ws://", 5) == 0) {
        use_ssl = 0;
        p = c->url + 5;
    } else {
        fprintf(stderr, "[WS] URL must start with ws:// or wss://: %s\n", c->url);
        return -1;
    }

    char host[256];
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (!slash) slash = p + strlen(p);

    if (colon && colon < slash) {
        size_t host_len = (size_t)(colon - p);
        if (host_len >= sizeof(host)) host_len = sizeof(host)-1;
        memcpy(host, p, host_len);
        host[host_len] = '\0';

        ccinfo.address = strdup(host);
        ccinfo.host    = ccinfo.address;
        ccinfo.port    = atoi(colon + 1);
        ccinfo.path    = (*slash ? slash : "/");
    } else {
        size_t host_len = (size_t)(slash - p);
        if (host_len >= sizeof(host)) host_len = sizeof(host)-1;
        memcpy(host, p, host_len);
        host[host_len] = '\0';

        ccinfo.address = strdup(host);
        ccinfo.host    = ccinfo.address;
        ccinfo.path    = (*slash ? slash : "/");
    }

    if (use_ssl && c->ca_path[0] != '\0') {
        ccinfo.ssl_connection = LCCSCF_USE_SSL;
    }

    c->wsi = lws_client_connect_via_info(&ccinfo);
    if (!c->wsi) {
        fprintf(stderr, "[WS] Connection failed\n");
        return -1;
    }

    c->connected = 1;
    return 0;
}

int ws_client_enqueue_file(ws_client_t *c, const char *file_path) {
    // Optional encryption before sending
    if (c->key_mode[0]) {
        if (strcmp(c->key_mode, "symmetric") == 0) {
            const char *p = (c->key_path[0]) ? c->key_path : DEFAULT_SYM_KEY_PATH;

            unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
            if (load_or_create_symmetric_key(p, key, sizeof(key)) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to load symmetric key\n" RESET);
                return -1;
            }
            if (encrypt_file_symmetric(key, file_path, file_path) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to encrypt file %s (symmetric)\n" RESET, file_path);
                return -1;
            }

            fprintf(stderr, GREEN "[SUCCESS] File %s was encrypted and sent successfully (symmetric)\n" RESET, file_path);

        } else if (strcmp(c->key_mode, "asymmetric") == 0) {
            const char *pub = (c->key_path[0]) ? c->key_path : DEFAULT_PUB_KEY_PATH;
            const char *pr  = DEFAULT_SYM_KEY_PATH;

            unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
            if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof(pub_key)) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to load asymmetric key\n" RESET);
                return -1;
            }
            if (encrypt_file_asymmetric(pub_key, file_path, file_path, c->enc_all) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to encrypt file %s (asymmetric)\n" RESET, file_path);
                return -1;
            }

            fprintf(stderr, GREEN "[SUCCESS] File %s was encrypted and sent successfully (asymmetric)\n" RESET, file_path);
        }
    }

    // grow queue + status arrays
    if (c->file_count == c->file_cap) {
        int new_cap = c->file_cap ? c->file_cap * 2 : 8;
        char **n = realloc(c->files, new_cap * sizeof(char*));
        if (!n) {
            fprintf(stderr, "[WS] Out of memory in enqueue\n");
            return -1;
        }
        c->files = n;

        if (ws_ensure_status_arrays(c, new_cap) != 0) {
            return -1;
        }
    }

    c->files[c->file_count] = strdup(file_path);
    if (!c->files[c->file_count]) {
        fprintf(stderr, "[WS] Out of memory strdup\n");
        return -1;
    }
    // ensure initial status
    c->sent_ok[c->file_count] = 0;
    c->retries[c->file_count] = 0;

    c->file_count++;

    // update global state to see new queue
    state.files      = (const char**)c->files;
    state.file_count = c->file_count;

    // ask LWS to call us when writable
    if (c->wsi) {
        lws_callback_on_writable(c->wsi);
    }

    fprintf(stderr, GREEN "[SUCCESS] File %s was sent successfully (no encryption)\n" RESET, file_path);

    return 0;
}

int ws_client_service(ws_client_t *c, int timeout_ms) {
    if (!c->ctx) return -1;

    int rc = lws_service(c->ctx, timeout_ms);
    if (rc < 0) c->connected = 0;

    if (!c->connected) {
        // check if there are unsent files
        int idx = 0;
        while (idx < c->file_count && c->sent_ok[idx]) idx++;

        // nothing left to send
        if (idx >= c->file_count) return 0;

        int max_attempts = g_retry_enabled ? g_max_retries : 1;

        if (c->retries[idx] >= max_attempts) {
            fprintf(
                stderr,
                "[WS] File %s failed after %d retries, skipping\n", c->files[idx], max_attempts
            );
            c->sent_ok[idx] = 1;

            // advance
            if (idx + 1 >= c->file_count) return 0;
            return 0;
        }

        c->retries[idx]++;
        fprintf(
            stderr,
            "[WS] Reconnecting for file %s (attempt %d/%d)\n", c->files[idx], c->retries[idx], max_attempts
        );

        // recreate connection
        struct lws_client_connect_info ccinfo;
        memset(&ccinfo, 0, sizeof(ccinfo));
        ccinfo.context = c->ctx;

        int use_ssl = 0;
        const char *p = NULL;

        if (strncmp(c->url, "wss://", 6) == 0) {
            use_ssl = 1;
            p = c->url + 6;
        } else if (strncmp(c->url, "ws://", 5) == 0) {
            use_ssl = 0;
            p = c->url + 5;
        } else {
            fprintf(stderr, "[WS] URL must start with ws:// or wss://: %s\n", c->url);
            return -1;
        }

        char host[256];
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        if (!slash) slash = p + strlen(p);

        if (colon && colon < slash) {
            size_t host_len = (size_t)(colon - p);
            if (host_len >= sizeof(host)) host_len = sizeof(host)-1;
            memcpy(host, p, host_len);
            host[host_len] = '\0';

            ccinfo.address = strdup(host);
            ccinfo.host    = ccinfo.address;
            ccinfo.port    = atoi(colon + 1);
            ccinfo.path    = (*slash ? slash : "/");
        } else {
            size_t host_len = (size_t)(slash - p);
            if (host_len >= sizeof(host)) host_len = sizeof(host)-1;
            memcpy(host, p, host_len);
            host[host_len] = '\0';

            ccinfo.address = strdup(host);
            ccinfo.host    = ccinfo.address;
            ccinfo.path    = (*slash ? slash : "/");
        }

        if (use_ssl && c->ca_path[0] != '\0') {
            ccinfo.ssl_connection = LCCSCF_USE_SSL;
        }

        c->wsi = lws_client_connect_via_info(&ccinfo);
        if (!c->wsi) {
            fprintf(stderr, "[WS] Reconnection failed\n");
            return 0; // will try again on next service
        }

        c->connected = 1;
        state.current_file = idx;
        state.phase = 0;
        state.files = (const char**)c->files;
        state.file_count = c->file_count;
        strncpy(state.device_id, c->device_id, sizeof(state.device_id)-1);

        lws_callback_on_writable(c->wsi);
    }

    c->connected = (state.current_file < state.file_count); // if last file was sent, end the connection

    return rc;
}

void ws_client_mark_done(ws_client_t *c) {
    c->done_flag = 1;
    // ws_callback will see this and send {"type":"end"} when all files done
    if (c->wsi) lws_callback_on_writable(c->wsi);
}

void ws_client_destroy(ws_client_t *c) {
    if (c->ctx) {
        lws_context_destroy(c->ctx);
        c->ctx = NULL;
    }
    for (int i = 0; i < c->file_count; ++i) {
        free(c->files[i]);
    }
    free(c->files);
    free(c->sent_ok);
    free(c->retries);

    c->files = NULL;
    c->sent_ok = NULL;
    c->retries = NULL;
    c->file_count = c->file_cap = 0;
    c->connected = 0;
    c->done_flag = 0;
    c->end_sent  = 0;
}

#endif  // USE_WS