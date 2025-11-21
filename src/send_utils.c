#include <curl/curl.h>

int send_encrypted_file(const char* url, const char* enc_path, const char* cert) {
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

    curl_mime_name(part, "file");            // field name
    curl_mime_filedata(part, enc_path);  // path to encrypted file

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

