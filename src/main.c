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
        "  %s send  [--https|--ws]  <path> <url> "
        "[--encrypt symmetric|asymmetric] [--all] [--timeout <n>]\n"
        "  %s encrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"
        "  %s decrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n",
        prog, prog, prog
    );
}

int parse_args(int argc, char** argv, key_mode_config_t* cf) {
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    memset(cf, 0, sizeof(*cf));

    cf->mode      = argv[1];
    cf->timeout_secs = 0;   // default: no monitoring

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

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    key_mode_config_t cf;
    if (parse_args(argc, argv, &cf) != 0) return EXIT_FAILURE;

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

        // global TLS options
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, cf.cert_path);

        send_ctx_t sctx = {0};
        sctx.cf   = &cf;
        sctx.curl = curl;

        int ret = monitor_path(cf.init_path, cf.timeout_secs, send_file_callback, &sctx);

#ifdef USE_WS
        if (cf.use_ws && sctx.ws_count > 0) {
            int ws_ret = send_files_via_ws(cf.url, "pi", sctx.ws_files, sctx.ws_count, cf.cert_path);
            if (ws_ret != 0) ret = -1;
        }

        ws_queue_free(&sctx);
#else
        if (ret == 0 && cf.timeout_secs > 0 && !cf.use_ws) send_end_signal_via_https(curl, cf.url, cf.cert_path);
#endif
        
        curl_easy_cleanup(curl);
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

        return (monitor_path(cf.init_path, cf.timeout_secs, sym_file_callback, &sctx) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
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

        return (monitor_path(cf.init_path, cf.timeout_secs, asym_file_callback, &actx) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    fprintf(
        stderr,
        RED "[ERROR] Wrong arguments specified\n" RESET
    );
    return EXIT_FAILURE;
}