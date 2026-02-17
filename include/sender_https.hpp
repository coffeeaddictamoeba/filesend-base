#pragma once

#include "sender.hpp"

#if FILESEND_ENABLE_HTTP
#include <curl/curl.h>
#include <string>
#include <memory>

class HttpsSender : public Sender {
public:
    HttpsSender(
        const std::string& device_id,
        FilesendPolicy& policy
    );

    ~HttpsSender() override;

    bool send_file(const std::string& file_path) override;
    bool send_end() override;

private:
    std::string device_id_;
    const FilesendPolicy& policy_;

    CURL* curl_{nullptr};

    bool _send_file(const std::string& file_path);
    bool _send_end();
};
#endif // FILESEND_ENABLE_HTTP
