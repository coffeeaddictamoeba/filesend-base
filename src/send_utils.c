// send_utils.c
#include <curl/curl.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <string.h>
#include <stdio.h>

#include "../include/file_utils.h"
#include "../include/key_utils.h"
#include "../include/send_utils.h"

int send_file(CURL* curl, const char* url, const char* file_path, const char* cert) {
    CURLcode res;
    int ret = 0;

    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);

    curl_mime_name(part, "file");
    curl_mime_filedata(part, file_path);

    curl_mimepart *dev = curl_mime_addpart(mime);
    curl_mime_name(dev, "device_id");
    curl_mime_data(dev, "pi", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    // TLS options are assumed to be set once in main using cert
    if (cert != NULL) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(
            stderr,
            "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res)
        );
        ret = -1;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200 || http_code == 201) {
            fprintf(
                stderr,
                "[SUCCESS] Server successfully received file %s\n", file_path
            );
            ret = 0;
        } else {
            fprintf(
                stderr,
                "[ERROR] Server returned HTTP %ld\n", http_code
            );
            ret = -1;
        }
    }

    curl_mime_free(mime);
    return ret;
}

int send_encrypted_file(CURL* curl, const char* url, const char* file_path, const char* cert, const char* key_path, const char* key_mode, int enc_all) {
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

        return send_file(curl, url, file_path, cert);
    }

    // Asymmetric key mode (public/private key)
    else if (strcmp(key_mode, "asymmetric") == 0) {
        const char* pub = (key_path == NULL) ? DEFAULT_PUB_KEY_PATH : key_path;
        const char* pr  = DEFAULT_SYM_KEY_PATH;  // placeholder for creation

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

        return send_file(curl, url, file_path, cert);
    }

    return -1; // should not reach
}

// signal server that sending ended (no more files)
int send_end_signal(CURL *curl, const char *url, const char *cert) {
    CURLcode res;
    int ret = 0;

    curl_mime *mime = curl_mime_init(curl);

    // indicate "done"
    curl_mimepart *end = curl_mime_addpart(mime);
    curl_mime_name(end, "end");
    curl_mime_data(end, "1", CURL_ZERO_TERMINATED);

    curl_mimepart *dev = curl_mime_addpart(mime);
    curl_mime_name(dev, "device_id");
    curl_mime_data(dev, "pi", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    if (cert != NULL) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, cert);
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(
            stderr,
            "[WARN] send_end_signal failed: %s\n", curl_easy_strerror(res)
        );
        ret = -1;
    } else {
        fprintf(
            stderr, 
            "[SUCCESS] Sent end-of-stream signal to server\n"
        );
    }

    curl_mime_free(mime);
    return ret;
}