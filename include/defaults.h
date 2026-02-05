#ifndef DEFAULTS_H
#define DEFAULTS_H

#include <cstddef>
#include <cstring>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <system_error>

// Colorful logs.
#define RESET   "\033[0m"
#define RED     "\033[31m"      // Errors
#define YELLOW  "\033[33m"      // Warnings
#define GREEN   "\033[32m"      // Success

#define FILESEND_DB_PATH ".filesend_cache"
#define FILESEND_CONFIG_PATH "filesend_config"

#define DEFAULT_COMPRESSION_FORMAT "zip"

#define DEFAULT_DATE_FORMAT "%Y%m%d_%H%M%S"

#define DEFAULT_DEVICE_ID "pi"

// Default paths for creation of keys. Do not set to actual key locations.
#define DEFAULT_SYM_KEY_PATH "sym_key.bin"
#define DEFAULT_PR_KEY_PATH  "pr_key.bin"
#define DEFAULT_PUB_KEY_PATH "pub_key.bin"

#define DEFAULT_CA_CERT_PATH ""

#define DEFAULT_RETRIES 3
#define WAIT_BEFORE_RECONNECT 3000

#define DB_INIT_SIZE   128
#define MAX_SENT_FILES 4096

constexpr const char* PUB_KEY_ENV   = "PUB_KEY_PATH";
constexpr const char* PR_KEY_ENV    = "PR_KEY_PATH";
constexpr const char* SYM_KEY_ENV   = "SYM_KEY_PATH";
constexpr const char* CERT_PATH_ENV = "CERT_PATH";

constexpr const char* DEVICE_ID_ENV = "DEVICE_ID";

constexpr const char* COMPRESSION_FORMATS_AVAILABLE[] = {
    "zip",
    "tar",
    "tar.gz"
};

// Additional directory names specification can be found in "multithreading_utils.h"
constexpr const char* INBOX_OUTBOX_DIR  = ".filesend_outbox";
constexpr const char* INBOX_ARCHIVE_DIR = ".filesend_archive";
constexpr const char* INBOX_OUTTMP_DIR  = ".filesend_tmp";

constexpr const char* ENC = ".enc";

#endif // DEFAULTS_H