#pragma once

#include <string>
#include <memory>

#include "sender.hpp"

class HttpsSender : public Sender {
public:
    HttpsSender(
        const std::string& device_id,
        send_policy_t policy
    );

    ~HttpsSender() override;

    bool send_file(const std::string& file_path) override;
    bool send_end() override;

private:
    std::string device_id_;
    send_policy_t policy_;

    CURL* curl_{nullptr};

    bool _send_file(const std::string& file_path);
    bool _send_end();
};
