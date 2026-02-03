#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <cstddef>
#include <cstdint>
#include <stddef.h>
#include <stdint.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <string>

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include "defaults.h"
#include "key_utils.h"

#define CHUNK_SIZE  4096

#define ENC_FLAG_ENABLED    (1u << 0)
#define ENC_FLAG_SYMMETRIC  (1u << 1)
#define ENC_FLAG_ALL        (1u << 2)
#define ENC_FLAG_ARCHIVE    (1u << 3)
#define ENC_FLAG_FORCE      (1u << 4)

struct locked_fd {
    int fd = -1;

    explicit locked_fd(const char* path, int flags) {
        fd = open(path, flags);
        if (fd < 0) {
            throw std::runtime_error(std::string("open failed: ") + path);
        }
        if (flock(fd, LOCK_EX) != 0) {
            int e = errno;
            close(fd);
            fd = -1;
            throw std::runtime_error(std::string("flock failed: ") + path + " errno=" + std::to_string(e));
        }
    }

    ~locked_fd() { if (fd >= 0) close(fd); }
    locked_fd(const locked_fd&) = delete;
    locked_fd& operator=(const locked_fd&) = delete;
};

typedef struct {
    uint64_t size;
    uint64_t mtime;
    uint32_t pmode;
} FileMetadata;

int make_readonly(const char *path);

int match_pattern(
    const char* p, 
    const char* text
);

// Integrity check
int compute_file_sha256(
    const char *path, 
    unsigned char out[crypto_hash_sha256_BYTES]
);

int compute_file_sha256_hex(
    const char *path, 
    char *hex_out, 
    size_t hex_out_len
);

int verify_file_checksum(
    const char* file_path,
    const char* sha,
    size_t sha_len
);

// Encryption/decryption (plain)
int encrypt_file_symmetric(
    const unsigned char* key, 
    const char* plain_path, 
    const char* enc_path,
    int enc_all
);

int decrypt_file_symmetric(
    const unsigned char* key, 
    const char* enc_path, 
    const char* dec_path,
    int dec_all
);

int encrypt_file_asymmetric(
    const unsigned char* pub_key, 
    const char* plain_path, 
    const char* enc_path, 
    int enc_all
);

int decrypt_file_asymmetric(
    const unsigned char* pub_key, 
    const unsigned char* pr_key, 
    const char* enc_path, 
    const char* dec_path, 
    int dec_all
);

// Encryption/decryption (fd)
int encrypt_file_symmetric_fd(
    const unsigned char* key,
    int in_fd,
    const char* enc_path,
    int enc_all
);

int decrypt_file_symmetric_fd(
    const unsigned char* key,
    int in_fd,
    const char* dec_path,
    int dec_all
);

int encrypt_file_asymmetric_fd(
    const unsigned char* pub_key,
    int in_fd,
    const char* enc_path,
    int enc_all
);

int decrypt_file_asymmetric_fd(
    const unsigned char* pub_key, 
    const unsigned char* pr_key,
    int in_fd, 
    const char* dec_path, 
    int dec_all
);

#endif // FILE_UTILS_H
