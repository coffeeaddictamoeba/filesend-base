#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <string>
#include <memory>
#include <chrono>

#include <sodium.h>
#include <curl/curl.h>

#include "../include/defaults.h" 
#include "../include/sender_https.hpp"
#include "../include/sender_ws.hpp"
#include "../include/dir_utils.h"
#include "../include/file_utils.h"
#include "../include/db_utils.hpp"

const char* PUB_KEY_ENV   = "PUB_KEY_PATH";
const char* PR_KEY_ENV    = "PR_KEY_PATH";
const char* SYM_KEY_ENV   = "SYM_KEY_PATH";
const char* CERT_PATH_ENV = "CERT_PATH";

int process_path_encrypt_decrypt(const filesend_config_t& cf, const std::function<int(const std::string& src, const std::string& dest)>& fn) {
    struct stat st{};
    if (stat(cf.init_path, &st) != 0) {
        perror("[ERROR] stat init_path");
        return -1;
    }

    std::string init(cf.init_path);
    std::string destBase = cf.dest_path ? std::string(cf.dest_path) : std::string(cf.init_path);

    // Single file
    if (S_ISREG(st.st_mode)) {
        std::string src  = init;
        std::string dest;

        struct stat dstst{};
        if (stat(destBase.c_str(), &dstst) == 0 && S_ISDIR(dstst.st_mode)) {
            auto pos = src.find_last_of('/');
            std::string fname = (pos == std::string::npos) ? src : src.substr(pos + 1);
            dest = destBase + "/" + fname;
        } else {
            dest = destBase;
        }

        return fn(src, dest);
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(
            stderr,
            "[ERROR] %s is neither file nor directory\n", cf.init_path
        );
        return -1;
    }

    // Dir
    bool destIsDir = false;
    struct stat dstst{};
    if (stat(destBase.c_str(), &dstst) == 0) {
        destIsDir = S_ISDIR(dstst.st_mode);
    } else {
        if (mkdir(destBase.c_str(), 0700) == 0) {
            destIsDir = true;
        } else {
            destBase = init;
            destIsDir = true;
        }
    }

    DIR* dir = opendir(init.c_str());
    if (!dir) {
        perror("[ERROR] opendir init_path");
        return -1;
    }

    int ret = 0;
    struct dirent* ent;
    char path_buf[PATH_MAX];

    while ((ent = readdir(dir)) != nullptr) {
        if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        snprintf(path_buf, sizeof(path_buf), "%s/%s", init.c_str(), ent->d_name);

        struct stat fst{};
        if (stat(path_buf, &fst) != 0) {
            perror("[WARN] stat entry");
            ret = -1;
            continue;
        }

        if (!S_ISREG(fst.st_mode)) {
            continue;
        }

        std::string src  = path_buf;
        std::string dest;

        if (destIsDir) {
            dest = destBase + "/" + ent->d_name;
        } else {
            dest = src;
        }

        if (fn(src, dest) != 0) {
            fprintf(
                stderr,
                "[WARN] Failed to process %s\n", src.c_str()
            );
            ret = -1;
        }
    }

    closedir(dir);
    return ret;
}

static void usage(const char* prog) {
    std::fprintf(
        stderr,
        "Usage:\n"
        "  %s send  [--https|--ws]  <path> <url> "
        "[--encrypt symmetric|asymmetric] [--all] "
        "[--timeout <n>] [--retry <n>] [--no-retry]\n"
        "  %s encrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"
        "  %s decrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n",
        prog, prog, prog
    );
}

int parse_args(int argc, char** argv, filesend_config_t* cf) {
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    std::memset(cf, 0, sizeof(*cf));

    cf->mode          = argv[1];
    cf->timeout_secs  = 0;   // default: no monitoring
    cf->max_retries   = 3;
    cf->retry_enabled = 1;

    // envs
    cf->dec_key_path = std::getenv(PR_KEY_ENV);
    cf->cert_path    = std::getenv(CERT_PATH_ENV);

    if (std::strcmp(cf->mode, "send") == 0) {
        if (argc < 5) {
            std::fprintf(
                stderr,
                RED "[ERROR] send mode requires [--https|--ws] <path> <url>\n" RESET
            );
            usage(argv[0]);
            return -1;
        }

        cf->use_ws   = (std::strcmp(argv[2], "--ws") == 0);
        cf->init_path = argv[3];
        cf->url       = argv[4];

        for (int i = 5; i < argc; ++i) {
            const char* arg = argv[i];

            if (std::strcmp(arg, "--encrypt") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --encrypt requires 'symmetric' or 'asymmetric'\n" RESET
                    );
                    return -1;
                }

                cf->flags |= ENC_FLAG_ENABLED;
                const char* mode = argv[++i];

                if (std::strcmp(mode, "symmetric") == 0) {
                    cf->flags   |= ENC_FLAG_SYMMETRIC;
                    cf->key_path = std::getenv(SYM_KEY_ENV);
                } else if (std::strcmp(mode, "asymmetric") == 0) {
                    cf->key_path = std::getenv(PUB_KEY_ENV);
                } else {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] Only symmetric and asymmetric key modes are possible\n" RESET
                    );
                    return -1;
                }

            } else if (std::strcmp(arg, "--all") == 0) {
                cf->flags |= ENC_FLAG_ALL;

            } else if (std::strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }
                cf->timeout_secs = std::atoi(argv[++i]);
                if (cf->timeout_secs < 0) cf->timeout_secs = 0;

            } else if (std::strcmp(arg, "--retry") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --retry requires integer count\n" RESET
                    );
                    return -1;
                }
                cf->max_retries   = std::abs(std::atoi(argv[++i]));
                cf->retry_enabled = 1;

            } else if (std::strcmp(arg, "--no-retry") == 0) {
                cf->max_retries   = 1;
                cf->retry_enabled = 0;

            } else {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in send mode: %s\n" RESET, arg
                );
                return -1;
            }
        }

    } else if (std::strcmp(cf->mode, "encrypt") == 0 ||
               std::strcmp(cf->mode, "decrypt") == 0)
    {
        cf->init_path = argv[2];
        cf->flags    |= ENC_FLAG_ENABLED;

        for (int i = 3; i < argc; ++i) {
            const char* arg = argv[i];

            if (std::strcmp(arg, "--symmetric") == 0) {
                cf->flags   |= ENC_FLAG_SYMMETRIC;
                cf->key_path = std::getenv(SYM_KEY_ENV);

            } else if (std::strcmp(arg, "--asymmetric") == 0) {
                cf->key_path = std::getenv(PUB_KEY_ENV);

            } else if (std::strcmp(arg, "--all") == 0) {
                cf->flags |= ENC_FLAG_ALL;

            } else if (std::strcmp(arg, "--dest") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --dest requires a file/directory path\n" RESET
                    );
                    return -1;
                }
                cf->dest_path = argv[++i];

            } else if (std::strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }
                cf->timeout_secs = std::atoi(argv[++i]);
                if (cf->timeout_secs < 0) cf->timeout_secs = 0;

            } else {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in %s mode: %s\n" RESET,
                    cf->mode, arg
                );
                return -1;
            }
        }

        if (!cf->dest_path) {
            cf->dest_path = cf->init_path;
        }

    } else {
        std::fprintf(
            stderr,
            RED "[ERROR] Unknown mode: %s\n" RESET, cf->mode
        );
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

    filesend_config_t cf{};
    if (parse_args(argc, argv, &cf) != 0) {
        return EXIT_FAILURE;
    }

    if (sodium_init() < 0) {
        fprintf(
            stderr, 
            RED "[ERROR] sodium_init failed\n" RESET
        );
        return EXIT_FAILURE;
    }

    // SEND MODE
    if (strcmp(cf.mode, "send") == 0) {
        curl_global_init(CURL_GLOBAL_DEFAULT);

        if (!cf.cert_path) {
            fprintf(
                stderr,
                RED "[ERROR] CERT_PATH env variable not set\n" RESET
            );
            curl_global_cleanup();
            return EXIT_FAILURE;
        }

        // Retry policy
        int maxRetries = cf.retry_enabled ? cf.max_retries : 1;
        if (maxRetries <= 0) maxRetries = 1;

        retry_policy_t send_retry{
            maxRetries,
            std::chrono::milliseconds(1000)
        };

        retry_policy_t conn_retry{
            maxRetries,
            std::chrono::milliseconds(2000)
        };

        file_db db(cf.init_path); db.load();

        // Transport
        std::unique_ptr<Sender> sender;
        const std::string device_id = "pi";

        if (cf.use_ws) {
            sender = std::make_unique<WsSender>(
                cf.url,
                device_id,
                send_retry,
                conn_retry,
                cf.cert_path
            );
        } else {
            // HTTPS transport
            sender = std::make_unique<HttpsSender>(
                cf.url,
                cf.cert_path,
                send_retry
            );
        }

        enc_policy_t enc{
            static_cast<std::uint32_t>(cf.flags),
            cf.key_path ? cf.key_path : ""
        };

        FileSender s(*sender, enc, send_retry, &db);

        bool ok = s.send_files_from_path(
            cf.init_path,
            device_id,
            std::chrono::seconds(cf.timeout_secs)
        );

        sender->send_end(device_id);

        curl_global_cleanup();
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // ENCRYPT / DECRYPT MODES
    if (cf.flags & ENC_FLAG_SYMMETRIC) {
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        if (!cf.key_path) {
            cf.key_path = (char*)DEFAULT_SYM_KEY_PATH;
        }

        if (load_or_create_symmetric_key(cf.key_path, key, sizeof(key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create/load symmetric key\n" RESET
            );
            return EXIT_FAILURE;
        }

        auto fn = [&](const std::string& src, const std::string& dest) -> int {
            return encrypt_file_symmetric(key, src.c_str(), dest.c_str(), (cf.flags & ENC_FLAG_ALL));
        };

        int rc = process_path_encrypt_decrypt(cf, fn);
        return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    } else {
        bool is_decrypt = (std::strcmp(cf.mode, "decrypt") == 0);

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        unsigned char pr_key [crypto_box_SECRETKEYBYTES];

        if (!cf.key_path)     cf.key_path     = (char*)DEFAULT_PUB_KEY_PATH;
        if (!cf.dec_key_path) cf.dec_key_path = (char*)DEFAULT_PR_KEY_PATH;

        if (!is_decrypt) {
            // ENCRYPT
            if (load_or_create_asymmetric_key_pair(
                    cf.key_path,
                    cf.dec_key_path,
                    pub_key,
                    sizeof(pub_key)) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create/load asymmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }

            bool enc_all = (cf.flags & ENC_FLAG_ALL);

            auto fn = [&](const std::string& src, const std::string& dest) -> int {
                return encrypt_file_asymmetric(
                    pub_key,
                    src.c_str(),
                    dest.c_str(),
                    enc_all
                );
            };

            int rc = process_path_encrypt_decrypt(cf, fn);
            return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

        } else {
            // DECRYPT
            if (load_key(cf.key_path,     pub_key, sizeof(pub_key)) != 0 ||
                load_key(cf.dec_key_path, pr_key,  sizeof(pr_key))  != 0) {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }

            bool dec_all = (cf.flags & ENC_FLAG_ALL);

            auto fn = [&](const std::string& src, const std::string& dest) -> int {
                return decrypt_file_asymmetric(
                    pub_key,
                    pr_key,
                    src.c_str(),
                    dest.c_str(),
                    dec_all
                );
            };

            int rc = process_path_encrypt_decrypt(cf, fn);
            return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    fprintf(
        stderr, 
        RED "[ERROR] Wrong arguments specified\n" RESET
    );

    return EXIT_FAILURE;
}
