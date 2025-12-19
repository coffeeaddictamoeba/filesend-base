#pragma once

#include "sender.hpp"
#include "ws_client.hpp"

class WsSender : public Sender {
public:
    WsSender(
        const std::string& device_id,
        FilesendPolicy& policy
    );

    ~WsSender() override = default;

    bool send_file(const std::string& file_path) override;
    bool send_end() override;

private:
    std::string device_id_;
    const FilesendPolicy& policy_;

    WsClient client_;
    bool connected_{false};

    bool is_connected();
    bool _send_file(const std::string& file_path);
    bool _send_end();
};
