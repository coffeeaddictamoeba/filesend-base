#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <memory>

#include <sodium.h>
#include <curl/curl.h>

#include "../include/arg_utils.h"
#include "../include/sender_https.hpp"
#include "../include/sender_ws.hpp"
#include "../include/dir_utils.hpp"
#include "../include/send_utils.h"
#include "../include/db_utils.hpp"

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

#ifdef USE_MULTITHREADING
        bool ok = s->send_files_from_path_mt(cf.init_path, cf.nthreads);
#else
        bool ok = s->send_files_from_path(cf.init_path);
#endif
        sender->send_end();

        curl_global_cleanup();

        return ok ? EXIT_SUCCESS : EXIT_FAILURE;

    } else if (strcmp(cf.mode.c_str(), "verify") == 0) { // supports raw (32-byte) and hex (64-byte) SHA256; this code uses the latter as default
        const char* sha_received = argv[3];
        return verify_file_checksum(
            cf.init_path.c_str(), 
            sha_received,
            strlen(sha_received)
        ) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // ENCRYPT / DECRYPT MODES
    auto policy = cf.policy;
    DirectoryProcessor dp;

    if (policy.is_encryption_symmetric()) { // SYMMETRIC
        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        if (strcmp(cf.mode.c_str(), "decrypt") != 0) { // ENCRYPT
            if (load_or_create_symmetric_key(cf.policy.enc_p.key_path.c_str(), key, sizeof key) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create/load symmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto enc_sym = [&](int in_fd, const char* dst) -> int {
                return encrypt_file_symmetric_fd(
                    key, 
                    in_fd, 
                    dst, 
                    policy.is_encryption_for_all()
                );
            };

            return (dp.process_encrypt(cf.init_path, cf.dest_path, policy.is_encryption_with_archive(), policy.is_encryption_forced(), enc_sym) == 0) 
                ? EXIT_SUCCESS 
                : EXIT_FAILURE;

        } else { // DECRYPT

            if (load_key(cf.policy.enc_p.key_path.c_str(), key, sizeof key) != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto dec_sym = [&](int in_fd, const char* dst) -> int {
                return decrypt_file_symmetric_fd(
                    key,
                    in_fd,
                    dst,
                    policy.is_encryption_for_all()
                );
            };

            return (dp.process_decrypt(cf.init_path, cf.dest_path, policy.is_encryption_with_archive(), policy.is_encryption_forced(), dec_sym) == 0) 
                ? EXIT_SUCCESS 
                : EXIT_FAILURE;
        }

    } else { // ASYMMETRIC
 
        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        unsigned char pr_key [crypto_box_SECRETKEYBYTES];

        if (strcmp(cf.mode.c_str(), "decrypt") != 0) { // ENCRYPT
            if (load_or_create_asymmetric_key_pair(
                    cf.policy.enc_p.key_path.c_str(),
                    cf.policy.enc_p.dec_key_path.c_str(),
                    pub_key,
                    sizeof pub_key) != 0) 
            {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to create/load asymmetric key\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto enc_asym = [&](int in_fd, const char* dst) -> int {
                return encrypt_file_asymmetric_fd(
                    pub_key,
                    in_fd,
                    dst,
                    policy.is_encryption_for_all()
                );
            };

            return (dp.process_encrypt(cf.init_path, cf.dest_path, policy.is_encryption_with_archive(), policy.is_encryption_forced(), enc_asym) == 0) 
                ? EXIT_SUCCESS 
                : EXIT_FAILURE;

        } else { // DECRYPT

            if (load_key(cf.policy.enc_p.key_path.c_str(), pub_key, sizeof(pub_key))     != 0 ||
                load_key(cf.policy.enc_p.dec_key_path.c_str(), pr_key,  sizeof(pr_key))  != 0) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to load asymmetric key pair\n" RESET
                );
                return EXIT_FAILURE;
            }

            auto dec_asym = [&](int in_fd, const char* dst) -> int {
                return decrypt_file_asymmetric_fd(
                    pub_key,
                    pr_key,
                    in_fd,
                    dst,
                    policy.is_encryption_for_all()
                );
            };

            return (dp.process_decrypt(cf.init_path, cf.dest_path, policy.is_encryption_with_archive(), policy.is_encryption_forced(), dec_asym) == 0) 
                ? EXIT_SUCCESS 
                : EXIT_FAILURE;
        }
    }

    fprintf(stderr, RED "[ERROR] Wrong arguments specified\n" RESET);

    return EXIT_FAILURE; 
}
