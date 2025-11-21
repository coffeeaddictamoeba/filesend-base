#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <string.h>

#include "../include/file_utils.h"

int send_file(const char* url, const char* file_path, const char* cert) {
    CURL *curl = NULL;
    CURLcode res;
    int ret = 0;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        return -1;
    }

    // POST
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);

    curl_mime_name(part, "file");             // field name
    curl_mime_filedata(part, file_path);  // path to file

    // Optionally send device ID or metadata
    curl_mimepart *dev = curl_mime_addpart(mime);
    curl_mime_name(dev, "device_id");
    curl_mime_data(dev, "pi", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    // Verify server certificate
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, cert);  // CA that signed server.crt

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(
            stderr, 
            "curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
        );
        ret = -1;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200 || http_code == 201) { // success
            ret = 0;
        } else {
            fprintf(stderr, "Server returned HTTP %ld\n", http_code);
            ret = -1;
        }
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return ret;
}

int send_encrypted_file(const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all) {
    // Symmetric key mode
    if (strcmp(key_mode, "symmetric") == 0) {
        const char* p = (key_path == NULL) ? DEFAULT_SYM_KEY_PATH : key_path;

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        if (load_or_create_symmetric_key(p, key, sizeof(key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create symmetric key\n" RESET
            );
            return -1;
        }

        if (encrypt_file_symmetric(key, file_path, file_path) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to encrypt the file: %s (symmetric encryption)\n" RESET, file_path
            );
            return -1;
        }

        return send_file(url, file_path, cert);
    }

    // Asymmetric key mode (public/private key)
    else if (strcmp(key_mode, "asymmetric") == 0) {

        const char* pub = (key_path == NULL) ? DEFAULT_PUB_KEY_PATH : key_path;
        const char* pr = DEFAULT_SYM_KEY_PATH;    // safeguard for create

        unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
        if (load_or_create_asymmetric_key_pair(pub, pr, pub_key, sizeof(pub_key)) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to create asymmetric key\n" RESET
            );
            return -1;
        }
            
        if (encrypt_file_asymmetric(pub_key, file_path, file_path, enc_all) != 0) {
            fprintf(
                stderr,
                RED "[ERROR] Failed to encrypt the file: %s (asymmetric encryption)\n" RESET, file_path
            );
            return -1;
        }

        return send_file(url, file_path, cert);
    }

    return -1; // should not reach
}


