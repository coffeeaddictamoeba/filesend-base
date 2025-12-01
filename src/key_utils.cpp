#include <fcntl.h>
#include <sodium.h>
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "../include/key_utils.h"

namespace {
    struct safe_fd {
        int fd;
        explicit safe_fd(int f) : fd(f) {}
        ~safe_fd() {
            if (fd >= 0) {
                ::close(fd);
            }
        }

        // non-copyable
        safe_fd(const safe_fd&) = delete;
        safe_fd& operator=(const safe_fd&) = delete;

        // movable
        safe_fd(safe_fd&& other) noexcept : fd(other.fd) {
            other.fd = -1;
        }
        safe_fd& operator=(safe_fd&& other) noexcept {
            if (this != &other) {
                if (fd >= 0) ::close(fd);
                fd = other.fd;
                other.fd = -1;
            }
            return *this;
        }
    };
} // namespace

int load_key(const char* key_path, unsigned char* key, size_t key_len) {
    int fd = ::open(key_path, O_RDONLY);
    if (fd < 0) {
        perror(RED "open key file (read)" RESET);
        return -1;
    }
    safe_fd guard(fd);

    ssize_t n = ::read(fd, key, key_len);
    if (n != static_cast<ssize_t>(key_len)) {
        fprintf(
            stderr,
            RED "[ERROR] Key file size mismatch\n" RESET
        );
        return -1;
    }

    return 0;
}

int save_key(const char* key_path, unsigned char* key, size_t key_len) {
    int fd = ::open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror(RED "open key file (create)" RESET);
        return -1;
    }
    safe_fd guard(fd);

    ssize_t n = ::write(fd, key, key_len);
    if (n != static_cast<ssize_t>(key_len)) {
        perror(RED "write key" RESET);
        return -1;
    }

    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        perror(RED "fchmod" RESET);
        return -1;
    }

    return 0;
}

int create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len) {
    randombytes_buf(key, key_len);

    if (save_key(key_path, key, key_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] save_key failed\n" RESET
        );
        return -1;
    }

    return 0;
}

int load_or_create_symmetric_key(const char* key_path, unsigned char* key, size_t key_len) {
    struct stat st{};
    if (::stat(key_path, &st) == 0) {
        return load_key(key_path, key, key_len);
    }
    return create_symmetric_key(key_path, key, key_len);
}

int create_asymmetric_key_pair(const char* pub_key_path, const char* pr_key_path, unsigned char* pub_key, size_t pub_key_len) {
    unsigned char pr_key[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pub_key, pr_key);

    FILE* fpk = std::fopen(pub_key_path, "wb");
    FILE* fsk = std::fopen(pr_key_path, "wb");
    if (!fpk || !fsk) {
        perror(RED "open key file (create asymmetric key pair)" RESET);
        if (fpk) std::fclose(fpk);
        if (fsk) std::fclose(fsk);
        return -1;
    }

    size_t written_pub = std::fwrite(pub_key, 1, pub_key_len, fpk);
    size_t written_pr  = std::fwrite(pr_key, 1, sizeof(pr_key), fsk);

    std::fclose(fpk);
    std::fclose(fsk);

    if (written_pub != pub_key_len || written_pr != sizeof(pr_key)) {
        fprintf(
            stderr,
            RED "[ERROR] Failed to write asymmetric key pair\n" RESET
        );
        return -1;
    }

    return 0;
}

int load_or_create_asymmetric_key_pair(const char* pub_key_path, const char* pr_key_path, unsigned char* pub_key, size_t pub_key_len) {
    struct stat pub_st{};
    struct stat pr_st{};

    if (::stat(pub_key_path, &pub_st) == 0 || ::stat(pr_key_path, &pr_st) == 0) {
        return load_key(pub_key_path, pub_key, pub_key_len);
    }

    return create_asymmetric_key_pair(pub_key_path, pr_key_path, pub_key, pub_key_len);
}

int create_sealed_key(unsigned char* file_key, size_t file_key_len, unsigned char* pub_key, unsigned char* sealed_key, size_t sealed_key_len, const char* sealed_key_path) {
    randombytes_buf(file_key, file_key_len);

    if (crypto_box_seal(sealed_key, file_key, file_key_len, pub_key) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] crypto_box_seal failed\n" RESET
        );
        return -1;
    }

    if (save_key(sealed_key_path, sealed_key, sealed_key_len) != 0) {
        fprintf(
            stderr,
            RED "[ERROR] save_key failed\n" RESET
        );
        return -1;
    }

    return 0;
}