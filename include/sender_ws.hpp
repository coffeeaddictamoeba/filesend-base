#pragma once

#include "sender.hpp"
#include "ws_client.hpp"

class WsSender : public Sender {
public:
    WsSender(
        const std::string& url,
        const std::string& device_id,
        retry_policy_t retry_send,
        retry_policy_t retry_connect,
        const std::string& cert_path
    );

    ~WsSender() override = default;

    bool send_file(
        const std::string& file_path,
        const std::string& device_id,
        uint32_t flags
    ) override;

    bool send_end(const std::string& device_id) override;

private:
    std::string url_;
    std::string device_id_;
    retry_policy_t retry_send_;
    retry_policy_t retry_connect_;

    WsClient client_;
    bool connected_{false};

    bool is_connected();
    bool _send_file(const std::string& path, uint32_t flags);
    bool _send_end();
};
