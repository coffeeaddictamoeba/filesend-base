#include <thread>

#include "../include/sender_ws.hpp"

WsSender::WsSender(const std::string& device_id, send_policy_t& policy)
    : Sender(policy),
      device_id_(device_id),
      policy_(policy),
      client_(policy_.url, device_id, policy_.cert_path) {}

bool WsSender::is_connected() {
    if (connected_) return true;

    bool ok = run_with_retries(
        policy_.retry_connect,
        "WS connect",
        [&]() {
            int rc = client_.connect();
            if (rc == 0) {
                connected_ = true;
                return true;
            }
            return false;
        });

    return ok;
}

bool WsSender::_send_file(const std::string& file_path) {
    if (!is_connected()) return false;

    int rc = client_.send_file(file_path, policy_.retry_send.max_attempts, policy_.enc_p.flags);
    if (rc != 0) {
        connected_ = false; // will reconnect next time
        return false;
    }
    return true;
}

bool WsSender::send_file(const std::string& file_path) {
    return run_with_retries(
        policy_.retry_send,
        "WS send_file(" + file_path + ")",
        [&]() { return _send_file(file_path); }
    );
}

bool WsSender::_send_end() {
    if (!is_connected()) return false;

    int rc = client_.send_end();
    if (rc != 0) {
        connected_ = false;
        return false;
    }
    return true;
}

bool WsSender::send_end() {
    return run_with_retries(
        policy_.retry_send,
        "WS send_end",
        [&]() { return _send_end(); }
    );
}
