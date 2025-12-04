#pragma once

#include <cstdint>
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
struct retry_policy_t {
    int max_attempts{DEFAULT_RETRIES};
    std::chrono::milliseconds delay{WAIT_BEFORE_RECONNECT};

    bool enabled() const { return max_attempts > 1; }
};

// Encryption configuration
struct enc_policy_t {
    uint32_t flags{0};         // |Res|Res|All|Sym|Enc|
    std::string key_path;      // could be symmetric or public key path depending on flags
    std::string dec_key_path;  // only for decrypt
};

// Send configuration
struct send_policy_t {
    std::chrono::seconds timeout;
    retry_policy_t retry_send;
    retry_policy_t retry_connect;
    enc_policy_t enc_p;
    std::string cert_path;
    std::string url;
};

class Sender {
public:
    virtual ~Sender() = default;

    virtual send_policy_t get_policy() const { return policy_;}

    // Send ONE file. Path may be already encrypted; flags tell server how to handle.
    virtual bool send_file(const std::string& file_path) = 0;

    // Optional end-of-batch signal
    virtual bool send_end() = 0;

private:
    send_policy_t policy_;
};

// run with retries
template <typename func>
bool run_with_retries(const retry_policy_t& policy, const std::string& what, func&& f) {
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
inline bool encrypt_in_place(const send_policy_t& policy, const std::string& file_path) {
    if (!(policy.enc_p.flags & ENC_FLAG_ENABLED)) return true;

    const char* key_path = policy.enc_p.key_path.empty() ? nullptr : policy.enc_p.key_path.c_str();

    if (policy.enc_p.flags & ENC_FLAG_SYMMETRIC) {
        const char* p = key_path ? key_path : DEFAULT_SYM_KEY_PATH;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(p, key, sizeof(key)) != 0) {
            fprintf(
                stderr, 
                "[ERROR] Failed to load/create symmetric key\n"
            );
            return false;
        }

        if (encrypt_file_symmetric(key, file_path.c_str(), file_path.c_str(), (policy.enc_p.flags & ENC_FLAG_ALL)) != 0) {
            fprintf(
                stderr,
                "[ERROR] Failed to encrypt %s (symmetric)\n", file_path.c_str()
            );
            return false;
        }
    } else {
        const char* pub = key_path ? key_path : DEFAULT_PUB_KEY_PATH;
        const char* pr  = DEFAULT_SYM_KEY_PATH; // dummy for keypair creation

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof(pub_key)) != 0) {
            fprintf(
                stderr, 
                "[ERROR] Failed to load/create asymmetric key\n"
            );
            return false;
        }

        if (encrypt_file_asymmetric(pub_key, file_path.c_str(), file_path.c_str(), (policy.enc_p.flags & ENC_FLAG_ALL)) != 0) {
            fprintf(
                stderr,
                "[ERROR] Failed to encrypt %s (asymmetric)\n", file_path.c_str()
            );
            return false;
        }
    }

    return true;
}