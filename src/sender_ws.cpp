#include <thread>

#include "../include/sender_ws.hpp"

WsSender::WsSender(const std::string& url, const std::string& device_id, retry_policy_t retry_send, retry_policy_t retry_connect, const std::string& cert_path)
    : url_(url),
      device_id_(device_id),
      retry_send_(retry_send),
      retry_connect_(retry_connect),
      client_(url, device_id, cert_path) {
}

bool WsSender::is_connected() {
    if (connected_) return true;

    bool ok = run_with_retries(
        retry_connect_,
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

bool WsSender::_send_file(const std::string& file_path, uint32_t flags) {
    if (!is_connected()) return false;

    int rc = client_.send_file(file_path, retry_send_.max_attempts, flags);
    if (rc != 0) {
        connected_ = false; // will reconnect next time
        return false;
    }
    return true;
}

bool WsSender::send_file(const std::string& file_path, const std::string& device_id, uint32_t flags) {
    (void)device_id; // device id is already embedded in WsClient handshake/header

    return run_with_retries(
        retry_send_,
        "WS send_file(" + file_path + ")",
        [&]() { return _send_file(file_path, flags); }
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

bool WsSender::send_end(const std::string& device_id) {
    (void)device_id; // device id known by WsClient

    return run_with_retries(
        retry_send_,
        "WS send_end",
        [&]() { return _send_end(); }
    );
}
