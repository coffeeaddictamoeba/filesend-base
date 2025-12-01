#pragma once

#include <string>
#include <memory>

#include "../include/sender.hpp"

class HttpsSender : public Sender {
public:
    HttpsSender(
        const std::string& url, 
        const std::string& cert_path, 
        retry_policy_t retry
    );

    ~HttpsSender() override;

    bool send_file(
        const std::string& file_path, 
        const std::string& device_id,
        uint32_t flags
    ) override;

    bool send_end(const std::string& device_id) override;

private:
    std::string url_;
    std::string cert_path_;
    retry_policy_t retry_;

    CURL* curl_{nullptr};

    bool _send_file(
        const std::string& file_path,
        const std::string& device_id,
        uint32_t flags
    );

    bool _send_end(const std::string& device_id);
};
