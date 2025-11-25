#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_WS
#include <libwebsockets.h>
#endif

#include "../include/file_utils.h"
#include "../include/key_utils.h"
#include "../include/send_utils.h"

int send_file_via_https(CURL* curl, const char* url, const char* file_path, const char* cert) {
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
            "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
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
            ret = 0;
        } else {
            fprintf(
                stderr,
                "[ERROR] Server returned HTTP %ld\n", http_code
            );
            ret = -1;
        }
    }

    curl_mime_free(mime);
    return ret;
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
    CURLcode res;
    int ret = 0;

    curl_mime *mime = curl_mime_init(curl);

    // indicate "done"
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
            YELLOW "[WARN] send_end_signal failed: %s\n" RESET, curl_easy_strerror(res)
        );
        ret = -1;
    } else {
        fprintf(
            stdout, 
            GREEN "[SUCCESS] Sent end-of-stream signal to server\n" RESET
        );
    }

    curl_mime_free(mime);
    return ret;
}

#ifdef USE_WS
client_state_t state;

int ws_callback(struct lws *wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
    switch(reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_user("[WS] Connected to server\n");
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            if (state.current_file >= state.file_count) {
                // send "end"
                char msg[256];
                snprintf(msg, sizeof(msg), "{\"type\":\"end\"}");

                size_t n = strlen(msg);
                unsigned char* buf = malloc(LWS_PRE + n);
                memcpy(&buf[LWS_PRE], msg, n);

                lwsl_user("[WS] Sending end\n");
                lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
                free(buf);

                return 0;
            }

            const char* path = state.files[state.current_file];
            const char* filename = strrchr(path, '/');

            if (!filename) filename = path; else filename++;

            if (state.phase == 0) {
                // send header JSON
                char json[512];
                snprintf(
                    json, 
                    sizeof(json), 
                    "{\"type\":\"file\",\"filename\":\"%s\",\"device_id\":\"%s\"}", filename, state.device_id
                );

                size_t n = strlen(json);
                unsigned char* buf = malloc(LWS_PRE + n);
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
                    // send binary frame
                    unsigned char* buf = malloc(LWS_PRE + r);
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
                char json[128];
                snprintf(json, sizeof(json), "{\"type\":\"file_end\"}");

                size_t n = strlen(json);
                unsigned char* buf = malloc(LWS_PRE + n);
                memcpy(&buf[LWS_PRE], json, n);

                lwsl_user("[WS] Sending file_end for file %d\n", state.current_file);
                lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
                free(buf);

                state.phase = 3;
                break;
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE:
            lwsl_user("[WS] Received reply: %.*s\n", (int)len, (char*)in);

            // server confirms file_done -> next file
            if (state.phase == 3) {
                state.current_file++;
                state.phase = 0;
                lws_callback_on_writable(wsi);
            }

            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            lwsl_err("[WS] Connection error\n");
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            lwsl_user("[WS] Connection closed\n");
            break;
        
        default:
            break;
        }
    return 0;
}

int send_files_via_ws(const char* ws_url, const char* device_id, const char** files, int file_count, const char* cert) {
    strcpy(state.device_id, device_id);
    state.files        = files;
    state.file_count   = file_count;
    state.current_file = 0;
    state.phase        = 0;

    struct lws_protocols protocols[] = {
        { "ws-protocol", ws_callback, 0, 4096 },
        { NULL, NULL, 0, 0 }
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port      = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;

    info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    int use_ssl = 0;
    const char *p = NULL;

    if (strncmp(ws_url, "wss://", 6) == 0) {
        use_ssl = 1;
        p = ws_url + 6;
    } else if (strncmp(ws_url, "ws://", 5) == 0) {
        use_ssl = 0;
        p = ws_url + 5;
    } else {
        fprintf(stderr, "[WS] URL must start with ws:// or wss://: %s\n", ws_url);
        return -1;
    }

    if (use_ssl && cert) {
        info.ssl_ca_filepath = cert;
    }

    struct lws_context* context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "[WS] Failed to create context\n");
        return -1;
    }

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = context;

    // defaults
    ccinfo.address = "127.0.0.1";
    ccinfo.port    = 8444;
    ccinfo.path    = "/";
    ccinfo.host    = ccinfo.address;

    char host[256];
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (!slash) slash = p + strlen(p); // no path, host[:port] only

    if (colon && colon < slash) {
        // ws[s]://host:port/path
        size_t host_len = (size_t)(colon - p);
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        memcpy(host, p, host_len);
        host[host_len] = '\0';

        ccinfo.address = strdup(host);
        ccinfo.host    = ccinfo.address;
        ccinfo.port    = atoi(colon + 1);
        ccinfo.path    = (*slash ? slash : "/");
    } else {
        // ws[s]://host/path
        size_t host_len = (size_t)(slash - p);
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        memcpy(host, p, host_len);
        host[host_len] = '\0';

        ccinfo.address = strdup(host);
        ccinfo.host    = ccinfo.address;
        ccinfo.path    = (*slash ? slash : "/");
    }

    if (use_ssl && cert) {
        ccinfo.ssl_connection = LCCSCF_USE_SSL;
    }

    if (!lws_client_connect_via_info(&ccinfo)) {
        fprintf(stderr, "[WS] Connection failed\n");
        lws_context_destroy(context);
        return -1;
    }

    // Event loop
    while (lws_service(context, 100) >= 0) { /* loop until closed */ }

    lws_context_destroy(context);
    return 0;
}

int send_encrypted_files_via_ws(const char* ws_url, const char* device_id, const char** files, int file_count, const char* cert, const char* key_mode, const char* key_path, int enc_all) {
    if (!key_mode) {
        fprintf(stderr, "[WS] send_encrypted_files_via_ws: key_mode is NULL\n");
        return -1;
    }

    if (strcmp(key_mode, "symmetric") == 0) {
        const char* p = (key_path == NULL) ? DEFAULT_SYM_KEY_PATH : key_path;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(p, key, sizeof(key)) != 0) {
            fprintf(stderr, RED "[ERROR] Failed to create/load symmetric key\n" RESET);
            return -1;
        }

        for (int i = 0; i < file_count; ++i) {
            const char *path = files[i];
            if (encrypt_file_symmetric(key, path, path) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to encrypt file: %s (symmetric)\n" RESET, path);
                return -1;
            }
        }

        return send_files_via_ws(ws_url, device_id, files, file_count, cert);
    }

    else if (strcmp(key_mode, "asymmetric") == 0) {
        const char* pub = (key_path == NULL) ? DEFAULT_PUB_KEY_PATH : key_path;
        const char* pr  = DEFAULT_SYM_KEY_PATH;  // dummy for creation

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof(pub_key)) != 0) {
            fprintf(stderr, RED "[ERROR] Failed to create/load asymmetric key\n" RESET);
            return -1;
        }

        for (int i = 0; i < file_count; ++i) {
            const char *path = files[i];
            if (encrypt_file_asymmetric(pub_key, path, path, enc_all) != 0) {
                fprintf(stderr, RED "[ERROR] Failed to encrypt file: %s (asymmetric)\n" RESET, path);
                return -1;
            }
        }

        return send_files_via_ws(ws_url, device_id, files, file_count, cert);
    }

    fprintf(stderr, "[WS] send_encrypted_files_via_ws: unknown key_mode '%s'\n", key_mode);
    return -1;
}
#endif  // USE_WS