#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>

#include "../include/key_utils.h"
#include "../include/send_utils.h"
#include "../include/dir_utils.h"

const char* PUB_KEY_ENV   = "PUB_KEY_PATH";
const char* PR_KEY_ENV    = "PR_KEY_PATH";
const char* SYM_KEY_ENV   = "SYM_KEY_PATH";
const char* CERT_PATH_ENV = "CERT_PATH";

void usage(const char* prog) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s send  [--https|--ws]  <path> <url> [--encrypt symmetric|asymmetric] [--all] [--timeout <n>] [--retry <n>] [--no-retry]\n"
        "  %s encrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--timeout <n>]\n"
        "  %s decrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--timeout <n>]\n",
        prog, prog, prog
    );
}

int parse_args(int argc, char** argv, filesend_config_t* cf) {
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    memset(cf, 0, sizeof(*cf));

    cf->mode          = argv[1];
    cf->timeout_secs  = 0;       // default: no monitoring
    cf->max_retries   = 3;
    cf->retry_enabled = 1;

    // envs
    cf->public_key_path  = getenv(PUB_KEY_ENV);
    cf->private_key_path = getenv(PR_KEY_ENV);
    cf->sym_key_path     = getenv(SYM_KEY_ENV);
    cf->cert_path        = getenv(CERT_PATH_ENV);

    if (strcmp(cf->mode, "send") == 0) {
        if (argc < 4) {
            fprintf(
                stderr,
                RED "[ERROR] send mode requires <path> and <url>\n" RESET
            );
            usage(argv[0]);
            return -1;
        }

        cf->use_ws = (strcmp(argv[2], "--ws") == 0);
        cf->init_path = argv[3];
        cf->url = argv[4];

        for (int i = 5; i < argc; ++i) {
            const char *arg = argv[i];

            if (strcmp(arg, "--encrypt") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --encrypt requires 'symmetric' or 'asymmetric'\n" RESET
                    );
                    return -1;
                }

                const char* mode = argv[++i];
                if (strcmp(mode, "symmetric") == 0 || strcmp(mode, "asymmetric") == 0) {
                    cf->key_mode = (char*)mode;
                } else {
                    fprintf(
                        stderr,
                        RED "[ERROR] Unknown encrypt mode: %s\n" RESET, mode
                    );
                    return -1;
                }
            } else if (strcmp(arg, "--all") == 0) {
                cf->on_all = 1;
            } else if (strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }
                cf->timeout_secs = atoi(argv[++i]);
                if (cf->timeout_secs < 0) cf->timeout_secs = 0;
            } else if (strcmp(arg, "--retry") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --retry requires integer seconds\n" RESET
                    );
                    return -1;
                }
                cf->max_retries = abs(atoi(argv[++i]));
                cf->retry_enabled = 1;
            } else if (strcmp(arg, "--no-retry") == 0) {
                cf->max_retries = 1; // effectively "no retry", 1 attempt
                cf->retry_enabled = 0;
            } else {
                fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in send mode: %s\n" RESET, arg
                );
                return -1;
            }
        }

    } else if (strcmp(cf->mode, "encrypt") == 0 || strcmp(cf->mode, "decrypt") == 0) {
        cf->init_path = argv[2];

        for (int i = 3; i < argc; ++i) {
            const char *arg = argv[i];

            if (strcmp(arg, "--symmetric") == 0) {
                cf->key_mode = "symmetric";
            } else if (strcmp(arg, "--asymmetric") == 0) {
                cf->key_mode = "asymmetric";
            } else if (strcmp(arg, "--all") == 0) {
                cf->on_all = 1;
            } else if (strcmp(arg, "--dest") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --dest requires a file/directory path\n" RESET
                    );
                    return -1;
                }
                cf->dest_path = argv[++i];
            } else if (strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }
                cf->timeout_secs = atoi(argv[++i]);
                if (cf->timeout_secs < 0) cf->timeout_secs = 0;
            } else {
                fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in %s mode: %s\n" RESET, cf->mode, arg
                );
                return -1;
            }
        }

        if (!cf->key_mode) {
            fprintf(
                stderr,
                RED "[ERROR] %s mode requires --symmetric or --asymmetric\n" RESET, cf->mode
            );
            return -1;
        }

        if (cf->dest_path == NULL) {
            // For single file, this is "in-place".
            // For directory, we will treat dest_path as directory if given;
            // otherwise, files are processed "in place".
            cf->dest_path = cf->init_path;
        }

    } else {
        fprintf(stderr, RED "[ERROR] Unknown mode: %s\n" RESET, cf->mode);
        usage(argv[0]);
        return -1;
    }

    return 0;
}

#ifdef USE_WS
void ws_tick(void *ctx) {
    ws_client_t *client = (ws_client_t *)ctx;
    if (!client || !client->connected) return;

    // Pump libwebsockets a bunch of times non-blocking.
    // This decouples sending speed from the directory polling timeout.
    for (int i = 0; i < 50; ++i) {   // tune 10/50/100 as you need
        if (!client->connected) break;
        int rc = ws_client_service(client, 0);  // 0ms -> non-blocking
        if (rc < 0) break;
    }
}
#endif

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    filesend_config_t cf;
    if (parse_args(argc, argv, &cf) != 0) return EXIT_FAILURE;

    send_set_retry_options(cf.retry_enabled, cf.max_retries);

    if (sodium_init() < 0) {
        fprintf(
            stderr,
            RED "[ERROR] sodium_init failed\n" RESET
        );
        return EXIT_FAILURE;
    }

    // SEND MODE (file or directory, optional monitoring)
    if (strcmp(cf.mode, "send") == 0) {
        if (!cf.cert_path) {
            fprintf(
                stderr, 
                RED "[ERROR] CERT_PATH env variable not set\n" RESET
            );
            return EXIT_FAILURE;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            fprintf(stderr, RED "[ERROR] curl_easy_init failed\n" RESET);
            return EXIT_FAILURE;
        }

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, cf.cert_path);

        db_t sent_db;
        if (db_init(&sent_db, cf.init_path) != 0) {
            fprintf(
                stderr, 
                RED "[DB] init failed, continuing without skip\n" RESET
            );
            memset(&sent_db, 0, sizeof(sent_db));
        }

#ifdef USE_WS
        ws_client_t ws_client;
        memset(&ws_client, 0, sizeof(ws_client));

        if (cf.use_ws) {
            const char *key_path = NULL;
            if (cf.key_mode) {
                if (strcmp(cf.key_mode, "symmetric") == 0)
                    key_path = cf.sym_key_path ? cf.sym_key_path : DEFAULT_SYM_KEY_PATH;
                else
                    key_path = cf.public_key_path ? cf.public_key_path : DEFAULT_PUB_KEY_PATH;
            }

            if (ws_client_init(
                &ws_client,
                cf.url,
                "pi",
                cf.cert_path,
                cf.key_mode,   // may be NULL
                key_path,
                cf.on_all) != 0) {
                fprintf(stderr, RED "[ERROR] ws_client_init failed\n" RESET);
                curl_easy_cleanup(curl);
                return EXIT_FAILURE;
            }
        }

        ws_client.sent_db = &sent_db;
#endif

        send_ctx_t sctx = {0};
        sctx.cf   = &cf;
        sctx.curl = curl;
        sctx.sent_db = &sent_db;

#ifdef USE_WS
        sctx.ws   = cf.use_ws ? &ws_client : NULL;
#endif

        int ret = 0;

        if (!cf.use_ws) {
            // HTTPS
            ret = monitor(cf.init_path, cf.timeout_secs, send_file_callback, &sctx);
            if (ret == 0 && cf.timeout_secs > 0) send_end_signal_via_https(curl, cf.url, cf.cert_path);
        } else {
    #ifdef USE_WS
            // WS
            time_t start_time = time(NULL);

            ret = monitor_with_tick(
                cf.init_path,
                cf.timeout_secs,
                send_file_callback,
                &sctx,
                ws_tick,
                &ws_client
            );

            // no more files will be enqueued and flush "end"
            ws_client_mark_done(&ws_client);
            while (ws_client.connected) {
                ws_client_service(&ws_client, 100);

                if (cf.timeout_secs > 0) {
                    time_t now = time(NULL);
                    if (now - start_time >= cf.timeout_secs) {
                        fprintf(stderr,
                            "[WS] HARD TIMEOUT reached (%d seconds). Forcing exit.\n",
                            cf.timeout_secs
                        );
                        break;
                    }
                }
            }
#endif
        }

#ifdef USE_WS
        if (cf.use_ws) ws_client_destroy(&ws_client);
#endif
        curl_easy_cleanup(curl);
        db_free(&sent_db);
        return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // ENCRYPT / DECRYPT MODES
    if (!cf.key_mode) {
        fprintf(
            stderr,
            RED "[ERROR] %s mode requires key mode\n" RESET, cf.mode
        );
        return EXIT_FAILURE;
    }

    // Symmetric
    if (strcmp(cf.key_mode, "symmetric") == 0) {
        sym_ctx_t sctx;
        sctx.cf = &cf;

        if (!cf.sym_key_path) cf.sym_key_path = DEFAULT_SYM_KEY_PATH;

        if (load_or_create_symmetric_key(cf.sym_key_path, sctx.key, sizeof(sctx.key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create/load symmetric key\n" RESET
            );
            return EXIT_FAILURE;
        }

        return (monitor(cf.init_path, cf.timeout_secs, sym_file_callback, &sctx) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // Asymmetric
    else if (strcmp(cf.key_mode, "asymmetric") == 0) {
        asym_ctx_t actx;
        actx.cf = &cf;
        actx.is_decrypt = (strcmp(cf.mode, "decrypt") == 0);

        if (!cf.private_key_path) cf.private_key_path = DEFAULT_PR_KEY_PATH;
        if (!cf.public_key_path)  cf.public_key_path = DEFAULT_PUB_KEY_PATH;

        if (!actx.is_decrypt) {
            // ENCRYPT: only need pub_key
            if (load_or_create_asymmetric_key_pair(
                cf.public_key_path,
                cf.private_key_path,
                actx.pub_key,
                sizeof(actx.pub_key)) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create/load asymmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }
        } else {
            // DECRYPT: need both pub + private
            if (load_key(cf.public_key_path, actx.pub_key, sizeof(actx.pub_key)) != 0 ||
                load_key(cf.private_key_path, actx.pr_key, sizeof(actx.pr_key)) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }
        }

        return (monitor(cf.init_path, cf.timeout_secs, asym_file_callback, &actx) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    fprintf(
        stderr,
        RED "[ERROR] Wrong arguments specified\n" RESET
    );
    return EXIT_FAILURE;
}