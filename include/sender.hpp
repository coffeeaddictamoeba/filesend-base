#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <chrono>
#include <functional>
#include <memory>
#include <cstdio>

#include <curl/curl.h>
#include <thread>

extern "C" {
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
}

#include "defaults.h"
#include "file_utils.h"
#include "key_utils.h"

// Retry configuration
struct RetryPolicy {
    int max_attempts{DEFAULT_RETRIES};
    std::chrono::milliseconds delay{WAIT_BEFORE_RECONNECT};

    bool enabled() const { return max_attempts > 1; }
};

// Encryption configuration
struct EncryptionPolicy {
    std::string key_path;      // could be symmetric or public key path depending on flags
    std::string dec_key_path;  // only for decrypt
    uint32_t flags{0};         // |Res|Orig|All|Sym|Enc|
};

// Send configuration
struct FilesendPolicy {
    EncryptionPolicy enc_p;
    std::string cert_path;
    std::string url;
    RetryPolicy retry_send;
    RetryPolicy retry_connect;
    std::chrono::seconds timeout;

    bool is_encryption_needed()       const noexcept { return enc_p.flags & ENC_FLAG_ENABLED; }
    bool is_encryption_symmetric()    const noexcept { return enc_p.flags & ENC_FLAG_SYMMETRIC; }
    bool is_encryption_for_all()      const noexcept { return enc_p.flags & ENC_FLAG_ALL; }
    bool is_encryption_with_archive() const noexcept { return enc_p.flags & ENC_FLAG_ARCHIVE; }
    bool is_encryption_forced()       const noexcept { return enc_p.flags & ENC_FLAG_FORCE; }
};

class Sender {
public:
    explicit Sender(const FilesendPolicy& policy) : policy_(policy) {}

    virtual ~Sender() = default;

    const FilesendPolicy& get_policy() const noexcept { return policy_; }

    // Send ONE file. Path may be already encrypted; flags tell server how to handle.
    virtual bool send_file(const std::string& file_path) = 0;

    // Optional end-of-batch signal
    virtual bool send_end() = 0;

private:
    FilesendPolicy policy_;
};

// run with retries
template <typename func>
bool run_with_retries(const RetryPolicy& policy, const std::string& what, func&& f) {
    int attempts = 0;
    const int max_attempts = policy.enabled() ? policy.max_attempts : 1;

    while (attempts < max_attempts) {
        ++attempts;
        if (f()) return true;

        fprintf(
            stderr,
            RED "[ERROR] %s failed (attempt %d/%d)\n" RESET, what.c_str(), attempts, max_attempts
        );

        if (attempts >= max_attempts) return false;

        if (policy.delay.count() > 0) {
            std::this_thread::sleep_for(policy.delay);
        }
    }
    return false;
}

// encrypt in-place
static bool encrypt_to_path_fd(const FilesendPolicy& policy, int in_fd, const std::string& file_path, const std::string& enc_file_path) {
    if (file_path.empty()) return false;

    if (!(policy.is_encryption_needed())) {
        printf("[INFO] No encryption policy provided. Sending plain file.\n");
        return true;
    }

    if (enc_file_path.empty()) return false;

    const char* key_path = policy.enc_p.key_path.empty() ? nullptr : policy.enc_p.key_path.c_str();

    // SYMMETRIC ENCRYPTION
    if (policy.is_encryption_symmetric()) {
        const char* p = key_path ? key_path : DEFAULT_SYM_KEY_PATH;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(p, key, sizeof key) != 0) {
            fprintf(stderr, "[ERROR] Failed to load/create symmetric key\n");
            return false;
        }

        if (encrypt_file_symmetric_fd(key, in_fd, enc_file_path.c_str(), policy.is_encryption_for_all()) != 0) {
            fprintf(stderr, "[ERROR] Failed to encrypt %s (symmetric)\n", file_path.c_str());
            return false;
        }

    } else { // ASYMMETRIC ENCRYPTION

        const char* pr  = DEFAULT_PR_KEY_PATH; // dummy for keypair creation
        const char* pub = key_path ? key_path : DEFAULT_PUB_KEY_PATH;

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof pub_key) != 0) {
            fprintf(stderr,  "[ERROR] Failed to load/create asymmetric key\n");
            return false;
        }

        if (encrypt_file_asymmetric_fd(pub_key, in_fd, enc_file_path.c_str(), policy.is_encryption_for_all()) != 0) {
            fprintf(stderr, "[ERROR] Failed to encrypt %s (asymmetric)\n", file_path.c_str());
            return false;
        }
    }

    if (!policy.is_encryption_with_archive()) remove(file_path.c_str()); // leave only encrypted version

    return true;
}

static bool encrypt_to_path(const FilesendPolicy& policy, const std::string& file_path, const std::string& enc_file_path) {
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) return -1;
    int rc = encrypt_to_path_fd(policy, fd, file_path, enc_file_path);
    close(fd);
    return rc;
}