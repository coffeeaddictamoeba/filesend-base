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

#include "../include/arg_utils.h"
#include "../include/sender_https.hpp"
#include "../include/sender_ws.hpp"
#include "../include/dir_utils.h"
#include "../include/file_utils.h"
#include "../include/db_utils.hpp"

int process_path(const std::string& init, std::string& dest, const std::function<int(const std::string& src, const std::string& dest)>& fn) {
    if (init.find_first_of("*?") != std::string::npos) {
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

        if (dest.empty() || dest == init) {
            return process_dir(src_dir, src_dir, pattern, fn);
        } else {;
            return process_dir(src_dir, dest, pattern, fn);
        }
    }

    struct stat st{};
    if (stat(init.c_str(), &st) != 0) {
        perror("[ERROR] stat init_path");
        return -1;
    }

    // Single file
    if (S_ISREG(st.st_mode)) {
        dest = dest.empty() ? init : dest;

        struct stat dstst{};
        if (stat(dest.c_str(), &dstst) == 0 && S_ISDIR(dstst.st_mode)) {
            auto pos = init.find_last_of('/');
            dest += "/";
            dest += (pos == std::string::npos) ? init : init.substr(pos + 1);
        }

        return fn(init, dest);
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(
            stderr,
            "[ERROR] %s is neither file nor directory\n", init.c_str()
        );
        return -1;
    }

    const std::string pattern = "";
    return process_dir(init, dest, pattern, fn);
}

int main(int argc, char** argv) { 
    ArgParser a{}; 
    if (a.parse(argc, argv) != 0) return EXIT_FAILURE;

    FilesendConfig cf = a.get_config();

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

        SentFileDatabase db(cf.init_path); db.load();

        std::unique_ptr<Sender> sender;
        std::unique_ptr<FileBatch> batch;

        if (cf.use_ws) {
            // WS transport
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
            batch = std::make_unique<FileBatch>(cf.batch_size, cf.batch_format);
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

    } else if (strcmp(cf.mode.c_str(), "verify") == 0) { // supports raw (32-bit) and hex (64-bit) SHA256; this code uses the latter as default
        const char* sha_received = argv[3];
        return verify_file_checksum(
            cf.init_path.c_str(), 
            sha_received,
            strlen(sha_received)
        ) == 0 ? EXIT_SUCCESS : EXIT_FAILURE; // add dir + pattern-based as well?
    }

    // ENCRYPT / DECRYPT MODES
    bool on_all = (cf.policy.enc_p.flags & ENC_FLAG_ALL);

    if (cf.policy.enc_p.flags & ENC_FLAG_SYMMETRIC) { // SYMMETRIC
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        if (strcmp(cf.mode.c_str(), "decrypt") != 0) { // ENCRYPT
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

            return (process_path(cf.init_path, cf.dest_path, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

        } else { // DECRYPT

            if (load_key(cf.policy.enc_p.key_path.c_str(), key, sizeof(key)) != 0) {
                std::fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto fn = [&](const std::string& src, const std::string& dest) -> int {
                return decrypt_file_symmetric(
                    key,
                    src.c_str(),
                    dest.c_str(),
                    on_all
                );
            };

            return (process_path(cf.init_path, cf.dest_path, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }

    } else { // ASYMMETRIC

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

            return (process_path(cf.init_path, cf.dest_path, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

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

            return (process_path(cf.init_path, cf.dest_path, fn) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    fprintf(
        stderr, 
        RED "[ERROR] Wrong arguments specified\n" RESET
    );

    return EXIT_FAILURE;
}
