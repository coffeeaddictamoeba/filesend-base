#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <filesystem>
#include <string>
#include <memory>
#include <chrono>

#include <sodium.h>
#include <curl/curl.h>

#include "../include/config.h"
#include "../include/sender_https.hpp"
#include "../include/sender_ws.hpp"
#include "../include/dir_utils.h"
#include "../include/file_utils.h"
#include "../include/db_utils.hpp"

int process_path(const filesend_config_t& cf, const std::function<int(const std::string& src, const std::string& dest)>& fn) {
    std::string init(cf.init_path);

    const bool has_wildcards = init.find_first_of("*?") != std::string::npos;

    std::string dest_base = cf.dest_path.empty() ? init : cf.dest_path;

    if (has_wildcards) {
        std::string::size_type slash = init.find_last_of('/');
        std::string src_dir;
        std::string pattern;

        if (slash == std::string::npos) {
            src_dir = ".";
            pattern = init;
        } else {
            src_dir = init.substr(0, slash);
            pattern = init.substr(slash + 1);
        }

        struct stat st{};
        if (stat(src_dir.c_str(), &st) != 0) {
            perror("[ERROR] stat pattern directory");
            return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
            std::fprintf(
                stderr,
                "[ERROR] %s is not a directory\n", src_dir.c_str()
            );
            return -1;
        }

        if (cf.dest_path == cf.init_path) {
            dest_base = src_dir;
        }

        return process_dir(src_dir, dest_base, pattern, fn);
    }

    struct stat st{};
    if (stat(init.c_str(), &st) != 0) {
        perror("[ERROR] stat init_path");
        return -1;
    }

    // Single file
    if (S_ISREG(st.st_mode)) {
        std::string src = init;
        std::string dest;
        std::string base = cf.dest_path.empty() ? cf.init_path : cf.dest_path;

        struct stat dstst{};
        if (stat(base.c_str(), &dstst) == 0 && S_ISDIR(dstst.st_mode)) {
            auto pos = src.find_last_of('/');
            std::string fname = (pos == std::string::npos) ? src : src.substr(pos + 1);
            dest = base + "/" + fname;
        } else {
            dest = base;
        }

        return fn(src, dest);
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(
            stderr,
            "[ERROR] %s is neither file nor directory\n", cf.init_path.c_str()
        );
        return -1;
    }

    const std::string pattern = "";
    return process_dir(init, dest_base, pattern, fn);
}

void usage(const char* prog) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s send  [--https|--ws]  <path> <url> "
        "[--encrypt symmetric|asymmetric] [--all] "
        "[--timeout <n>] [--retry <n>] [--no-retry] [--batch <n> <format>]\n"
        "  %s encrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"
        "  %s decrypt <path> [--symmetric|--asymmetric] [--all] "
        "[--dest <file>] [--timeout <n>]\n"
        "  %s verify <path> <sha256>\n",
        prog, prog, prog, prog
    );
}

int parse_args(int argc, char** argv, filesend_config_t& cf) {
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    cf = {};

    cf.mode           = argv[1];
    cf.device_id      = "pi";
    cf.batch_size     = 1;
    cf.policy.timeout = std::chrono::seconds(0);

    if (std::strcmp(cf.mode.c_str(), "send") == 0) {
        if (argc < 5) {
            std::fprintf(
                stderr,
                RED "[ERROR] send mode requires [--https|--ws] <path> <url>\n" RESET
            );
            usage(argv[0]);
            return -1;
        }

        cf.use_ws     = (std::strcmp(argv[2], "--ws") == 0);
        cf.init_path  = argv[3];

        if (!fs::exists(cf.init_path)) {
            fprintf(
                stderr, 
                RED "[ERROR] There is no path with name \"%s\" \r\n" RESET, cf.init_path.c_str()
            );
            return -1;
        }

        cf.policy.url = argv[4];
        cf.policy.cert_path = getenv_or_default(
            CERT_PATH_ENV, 
            DEFAULT_CA_CERT_PATH
        );

        for (int i = 5; i < argc; ++i) {
            const char* arg = argv[i];

            if (std::strcmp(arg, "--encrypt") == 0) {
                if (i + 1 >= argc) {
                    fprintf(
                        stderr,
                        RED "[ERROR] --encrypt requires 'symmetric' or 'asymmetric'\n" RESET
                    );
                    return -1;
                }

                cf.policy.enc_p.flags |= ENC_FLAG_ENABLED;

                const char* mode = argv[++i];

                if (std::strcmp(mode, "symmetric") == 0) {
                    cf.policy.enc_p.flags   |= ENC_FLAG_SYMMETRIC;
                    cf.policy.enc_p.key_path = getenv_or_default(
                        SYM_KEY_ENV, 
                        DEFAULT_SYM_KEY_PATH
                    );
                } else if (std::strcmp(mode, "asymmetric") == 0) {
                    cf.policy.enc_p.key_path = getenv_or_default(
                        PUB_KEY_ENV, 
                        DEFAULT_PUB_KEY_PATH
                    );
                } else {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] Only symmetric and asymmetric key modes are possible\n" RESET
                    );
                    return -1;
                }

            } else if (std::strcmp(arg, "--all") == 0) {
                cf.policy.enc_p.flags |= ENC_FLAG_ALL;

            } else if (std::strcmp(arg, "--batch") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --batch requires integer size and compression format\n" RESET
                    );
                    return -1;
                }
                
                cf.batch_size = std::max((int)cf.batch_size, std::atoi(argv[++i]));

                if (i + 1 < argc) {
                    char* next_arg = argv[i+1];
                    for (const auto& format : COMPRESSION_FORMATS_AVAILABLE) {
                        if (strcmp(format, next_arg) == 0) {
                            cf.batch_format = next_arg;
                            break;
                        }
                    }
                }

                if (cf.batch_format.empty()) cf.batch_format = DEFAULT_COMPRESSION_FORMAT;

            } else if (std::strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }

                cf.policy.timeout = std::max(
                    cf.policy.timeout, 
                    std::chrono::seconds(std::atoi(argv[++i]))
                );

            } else if (std::strcmp(arg, "--retry") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --retry requires integer count\n" RESET
                    );
                    return -1;
                }

                // make separate options later
                cf.policy.retry_send.max_attempts 
                = cf.policy.retry_connect.max_attempts 
                = std::abs(std::atoi(argv[++i]));

            } else if (std::strcmp(arg, "--no-retry") == 0) {
                cf.policy.retry_send.max_attempts 
                = cf.policy.retry_connect.max_attempts 
                = 1;

            } else {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in send mode: %s\n" RESET, arg
                );
                return -1;
            }
        }

    } else if (std::strcmp(cf.mode.c_str(), "encrypt") == 0 || std::strcmp(cf.mode.c_str(), "decrypt") == 0) {
        cf.init_path = argv[2];
        cf.policy.enc_p.flags |= ENC_FLAG_ENABLED;

        if (strcmp(cf.mode.c_str(), "decrypt") == 0) {
            cf.policy.enc_p.dec_key_path = getenv_or_default(
                PR_KEY_ENV, 
                DEFAULT_PR_KEY_PATH
            );
        }

        for (int i = 3; i < argc; ++i) {
            const char* arg = argv[i];

            if (std::strcmp(arg, "--symmetric") == 0) {
                cf.policy.enc_p.flags   |= ENC_FLAG_SYMMETRIC;
                cf.policy.enc_p.key_path = getenv_or_default(
                    SYM_KEY_ENV, 
                    DEFAULT_SYM_KEY_PATH
                );
            } else if (std::strcmp(arg, "--asymmetric") == 0) {
                cf.policy.enc_p.key_path = getenv_or_default(
                    PUB_KEY_ENV, 
                    DEFAULT_PUB_KEY_PATH
                );

            } else if (std::strcmp(arg, "--all") == 0) {
                cf.policy.enc_p.flags |= ENC_FLAG_ALL;

            } else if (std::strcmp(arg, "--dest") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --dest requires a file/directory path\n" RESET
                    );
                    return -1;
                }
                cf.dest_path = argv[++i];

            } else if (std::strcmp(arg, "--timeout") == 0) {
                if (i + 1 >= argc) {
                    std::fprintf(
                        stderr,
                        RED "[ERROR] --timeout requires integer seconds\n" RESET
                    );
                    return -1;
                }

                cf.policy.timeout = std::max(
                    cf.policy.timeout, 
                    std::chrono::seconds(std::atoi(argv[++i]))
                );

            } else {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Unknown argument in %s mode: %s\n" RESET,
                    cf.mode.c_str(), arg
                );
                return -1;
            }
        }

        if (cf.dest_path.empty()) { cf.dest_path = cf.init_path; }
    
    } else if (std::strcmp(cf.mode.c_str(), "verify") == 0) {
        cf.init_path = argv[2];
        return 0;

    } else {
        std::fprintf(
            stderr,
            RED "[ERROR] Unknown mode: %s\n" RESET, cf.mode.c_str()
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
    if (parse_args(argc, argv, cf) != 0) return EXIT_FAILURE;

    if (sodium_init() < 0) {
        fprintf(
            stderr, 
            RED "[ERROR] sodium_init failed\n" RESET
        );
        return EXIT_FAILURE;
    }

    // SEND MODE
    if (strcmp(cf.mode.c_str(), "send") == 0) {
        curl_global_init(CURL_GLOBAL_DEFAULT);

        file_db db(cf.init_path); db.load();

        // Transport
        std::unique_ptr<Sender> sender;
        std::unique_ptr<batch_t> batch;

        if (cf.use_ws) {
            sender = std::make_unique<WsSender>(
                cf.device_id,
                cf.policy
            );
        } else {
            // HTTPS transport
            sender = std::make_unique<HttpsSender>(
                cf.device_id,
                cf.policy
            );
        }

        std::unique_ptr<FileSender> s;
        if (cf.batch_size > 1) {
            batch = std::make_unique<batch_t>(cf.batch_size, cf.batch_format);
            s = std::make_unique<FileSender>(
                *sender, 
                batch.get(),
                &db
            );
        } else {
            s = std::make_unique<FileSender>(
                *sender,
                &db
            );
        }
        
        bool ok = s->send_files_from_path(cf.init_path);

        sender->send_end();

        curl_global_cleanup();

        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    } else if (strcmp(cf.mode.c_str(), "verify") == 0) {
        const char* sha_received = argv[3];

        printf("[INFO] Checksum received: %s\n", sha_received);

        char sha_actual[crypto_hash_sha256_BYTES*2+1];
        if (compute_file_sha256_hex(cf.init_path.c_str(), sha_actual, sizeof(sha_actual)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to compute checksum of %s\n" RESET, cf.init_path.c_str() 
            );
            return -1;
        }

        printf("[INFO] Checksum computed: %s\n", sha_actual);

        if (sodium_memcmp(sha_received, sha_actual, crypto_hash_sha256_BYTES*2+1) == 0) {
            fprintf(
                stdout,
                GREEN "[SUCCESS] Checksum match: %s\n" RESET, cf.init_path.c_str() 
            );
            return EXIT_SUCCESS;
        }

        fprintf(
            stderr,
            RED "[ERROR] Checksum does not match: %s\n" RESET, cf.init_path.c_str() 
        );

        return EXIT_FAILURE;
    }

    // ENCRYPT / DECRYPT MODES
    bool on_all = (cf.policy.enc_p.flags & ENC_FLAG_ALL);

    if (cf.policy.enc_p.flags & ENC_FLAG_SYMMETRIC) {
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        if (load_or_create_symmetric_key(cf.policy.enc_p.key_path.c_str(), key, sizeof(key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create/load symmetric key\n" RESET
            );
            return EXIT_FAILURE;
        }

        auto fn = [&](const std::string& src, const std::string& dest) -> int {
            return encrypt_file_symmetric(
                key, 
                src.c_str(), 
                dest.c_str(), 
                on_all
            );
        };

        return (process_path(cf, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

    } else {

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        unsigned char pr_key [crypto_box_SECRETKEYBYTES];

        if (strcmp(cf.mode.c_str(), "decrypt") != 0) { // ENCRYPT
            if (load_or_create_asymmetric_key_pair(
                    cf.policy.enc_p.key_path.c_str(),
                    cf.policy.enc_p.dec_key_path.c_str(),
                    pub_key,
                    sizeof(pub_key)) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create/load asymmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto fn = [&](const std::string& src, const std::string& dest) -> int {
                return encrypt_file_asymmetric(
                    pub_key,
                    src.c_str(),
                    dest.c_str(),
                    on_all
                );
            };

            return (process_path(cf, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

        } else { // DECRYPT
            if (load_key(cf.policy.enc_p.key_path.c_str(), pub_key, sizeof(pub_key))     != 0 ||
                load_key(cf.policy.enc_p.dec_key_path.c_str(), pr_key,  sizeof(pr_key))  != 0) {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto fn = [&](const std::string& src, const std::string& dest) -> int {
                return decrypt_file_asymmetric(
                    pub_key,
                    pr_key,
                    src.c_str(),
                    dest.c_str(),
                    on_all
                );
            };

            return (process_path(cf, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    fprintf(
        stderr, 
        RED "[ERROR] Wrong arguments specified\n" RESET
    );

    return EXIT_FAILURE;
}
