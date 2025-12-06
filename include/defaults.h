#ifndef DEFAULTS_H
#define DEFAULTS_H

// Colorful logs.
#define RESET   "\033[0m"
#define RED     "\033[31m"      // Errors
#define YELLOW  "\033[33m"      // Warnings
#define GREEN   "\033[32m"      // Success

#define DB_NAME ".filesend_cache"

#define DEFAULT_COMPRESSION_FORMAT "tar"

#define DEFAULT_DATE_FORMAT "%Y%m%d_%H%M%S"

// Default paths for creation of keys. Do not set to actual key locations.
#define DEFAULT_SYM_KEY_PATH "sym_key.bin"
#define DEFAULT_PR_KEY_PATH  "pr_key.bin"
#define DEFAULT_PUB_KEY_PATH "pub_key.bin"
#define DEFAULT_CA_CERT_PATH "ca_cert.pem"

#define DEFAULT_RETRIES 3
#define WAIT_BEFORE_RECONNECT 3000

#define DB_INIT_SIZE   128
#define MAX_SENT_FILES 4096

#endif // DEFAULTS_H