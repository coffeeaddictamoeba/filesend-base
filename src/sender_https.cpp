#include <stdexcept>
#include <thread>

#include "../include/sender_https.hpp"

HttpsSender::HttpsSender(const std::string& url, const std::string& cert_path, retry_policy_t retry) : url_(url), cert_path_(cert_path), retry_(retry) {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("curl_easy_init failed");
    }

    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!cert_path_.empty()) {
        curl_easy_setopt(curl_, CURLOPT_CAINFO, cert_path_.c_str());
    }
}

HttpsSender::~HttpsSender() {
    if (curl_) {
        curl_easy_cleanup(curl_);
        curl_ = nullptr;
    }
}

bool HttpsSender::_send_file(const std::string& file_path, const std::string& device_id, uint32_t flags) {
    make_readonly(file_path.c_str());

    curl_mime* mime = curl_mime_init(curl_);
    if (!mime) return false;

    // file
    curl_mimepart* file_part = curl_mime_addpart(mime);
    curl_mime_name(file_part, "file");
    curl_mime_filedata(file_part, file_path.c_str());

    // device_id
    curl_mimepart* dev = curl_mime_addpart(mime);
    curl_mime_name(dev, "device_id");
    curl_mime_data(dev, device_id.c_str(), CURL_ZERO_TERMINATED);

    // flags
    char buf[32];
    snprintf(buf, sizeof(buf), "%u", flags);
    curl_mimepart* fl = curl_mime_addpart(mime);
    curl_mime_name(fl, "flags");
    curl_mime_data(fl, buf, CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
    curl_easy_setopt(curl_, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl_);
    bool ok = false;

    if (res != CURLE_OK) {
        fprintf(
            stderr,
            RED "[ERROR] HTTPS: curl_easy_perform() failed for %s: %s\n" RESET, file_path.c_str(), curl_easy_strerror(res)
        );
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200 || http_code == 201) {
            fprintf(
                stdout,
                GREEN "[SUCCESS] OK: server received %s (HTTP %ld)\n" RESET, file_path.c_str(), http_code
            );
            ok = true;
        } else {
            fprintf(
                stderr,
                RED "[ERROR] HTTPS: server returned HTTP %ld for %s\n" RESET, http_code, file_path.c_str()
            );
        }
    }

    curl_mime_free(mime);
    return ok;
}

bool HttpsSender::send_file(const std::string& file_path, const std::string& device_id, uint32_t flags) {
    return run_with_retries(
        retry_,
        "HTTPS send_file(" + file_path + ")",
        [&]() { return _send_file(file_path, device_id, flags); }
    );
}

bool HttpsSender::_send_end(const std::string& device_id) {
    curl_mime* mime = curl_mime_init(curl_);
    if (!mime) return false;

    // end flag
    curl_mimepart* end = curl_mime_addpart(mime);
    curl_mime_name(end, "end");
    curl_mime_data(end, "1", CURL_ZERO_TERMINATED);

    // device_id
    curl_mimepart* dev = curl_mime_addpart(mime);
    curl_mime_name(dev, "device_id");
    curl_mime_data(dev, device_id.c_str(), CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
    curl_easy_setopt(curl_, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl_);
    bool ok = false;

    if (res != CURLE_OK) {
        fprintf(
            stderr,
            RED "[ERROR] HTTPS: sendEnd failed: %s\n" RESET, curl_easy_strerror(res)
        );
    } else {
        fprintf(
            stdout,
            "[HTTPS] End-of-stream signal sent\n"
        );
        ok = true;
    }

    curl_mime_free(mime);
    return ok;
}

bool HttpsSender::send_end(const std::string& device_id) {
    return run_with_retries(
        retry_,
        "HTTPS send_end",
        [&]() { return _send_end(device_id); }
    );
}