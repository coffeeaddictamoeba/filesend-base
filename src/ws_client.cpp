#include <fstream>
#include <cstdio>
#include <string>

#include "../include/defaults.h"
#include "../include/ws_client.hpp"

WsClient::WsClient(const std::string& url, const std::string& device_id, const std::string& ca_cert)
    : url_(url),
      device_id_(device_id),
      ca_cert_(ca_cert),
      ssl_ctx_(ssl::context::tls_client),
      resolver_(ioc_) {
    parse_url();
    if (use_tls_) {
        ssl_ctx_.set_default_verify_paths();
        if (!ca_cert_.empty()) {
            ssl_ctx_.load_verify_file(ca_cert_);
        }
        ssl_ctx_.set_verify_mode(ssl::verify_peer);
    }
}

WsClient::~WsClient() {
    close();
}

void WsClient::parse_url() {
    constexpr const char* WS  = "ws://";
    constexpr const char* WSS = "wss://";

    std::string rest;
    if (url_.rfind(WSS, 0) == 0) {
        use_tls_ = true;
        rest = url_.substr(std::strlen(WSS));
    } else if (url_.rfind(WS, 0) == 0) {
        use_tls_ = false;
        rest = url_.substr(std::strlen(WS));
    } else {
        throw std::runtime_error(RED "URL must start with ws:// or wss://" RESET);
    }

    auto slash = rest.find('/');
    std::string host_port = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    target_ = (slash == std::string::npos) ? "/" : rest.substr(slash);

    auto colon = host_port.find(':');
    if (colon == std::string::npos) {
        host_ = host_port;
        port_str_ = use_tls_ ? "443" : "80";
    } else {
        host_ = host_port.substr(0, colon);
        port_str_ = host_port.substr(colon + 1);
    }
}

int WsClient::connect_plain() {
    try {
        auto results = resolver_.resolve(host_, port_str_);
        ws_plain_ = std::make_unique<websocket::stream<tcp::socket>>(ioc_);

        net::connect(ws_plain_->next_layer(), results.begin(), results.end());

        ws_plain_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_plain_->handshake(host_, target_);

        connected_ = true;
        fprintf(
            stdout, 
            GREEN "[WS] Connected (plain) to %s:%s%s\n" RESET, host_.c_str(), port_str_.c_str(), target_.c_str()
        );
        return 0;
    } catch (const std::exception& e) {
        fprintf(
            stderr, 
            RED "[WS] connect_plain exception: %s\n" RESET, e.what()
        );
        connected_ = false;
        return -1;
    }
}

int WsClient::connect_tls() {
    try {
        auto results = resolver_.resolve(host_, port_str_);
        ws_tls_ = std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(ioc_, ssl_ctx_);

        net::connect(ws_tls_->next_layer().next_layer(), results.begin(), results.end());

        ws_tls_->next_layer().handshake(ssl::stream_base::client);

        ws_tls_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_tls_->handshake(host_, target_);

        connected_ = true;
        fprintf(
            stdout, 
            GREEN "[WS] Connected (TLS) to %s:%s%s\n" RESET, host_.c_str(), port_str_.c_str(), target_.c_str()
        );
        return 0;
    } catch (const std::exception& e) {
        fprintf(
            stderr, 
            RED "[WS] connect_tls exception: %s\n" RESET, e.what()
        );
        connected_ = false;
        return -1;
    }
}

int WsClient::connect() {
    if (use_tls_) return connect_tls();
    return connect_plain();
}

void WsClient::close() {
    if (!connected_) return;
    try {
        beast::error_code ec;
        if (use_tls_) {
            if (ws_tls_) ws_tls_->close(websocket::close_code::normal, ec);
        } else {
            if (ws_plain_) ws_plain_->close(websocket::close_code::normal, ec);
        }
        if (ec) {
            fprintf(
                stderr, 
                RED "[WS] close error: %s\n" RESET, ec.message().c_str()
            );
        }
    } catch (...) {}
    connected_ = false;
}

int WsClient::send_file(const std::string& file_path, int max_attempts, uint32_t flags) {
    if (!connected_) {
        if (connect() != 0) return -1;
    }

    std::string filename;
    auto pos = file_path.find_last_of('/');
    filename = (pos == std::string::npos) ? file_path : file_path.substr(pos + 1);

    std::string header_json =
        std::string("{\"type\":\"file\",\"filename\":\"") +
        filename + "\",\"device_id\":\"" + device_id_ + "\",\"flags\":\"" + std::to_string(flags) + "\"}";

    try {
        auto send_text = [&](const std::string& s) {
            if (use_tls_) {
                ws_tls_->text(true);
                ws_tls_->write(net::buffer(s));
            } else {
                ws_plain_->text(true);
                ws_plain_->write(net::buffer(s));
            }
        };

        auto send_bin = [&](const void* data, std::size_t sz) {
            if (use_tls_) {
                ws_tls_->binary(true);
                ws_tls_->write(net::buffer(data, sz));
            } else {
                ws_plain_->binary(true);
                ws_plain_->write(net::buffer(data, sz));
            }
        };

        send_text(header_json);

        std::ifstream f(file_path, std::ios::binary);
        if (!f) {
            std::perror(RED "[WS] fopen file" RESET);
            return -1;
        }

        char buf[64*1024];
        while (f) {
            f.read(buf, sizeof(buf));
            std::streamsize n = f.gcount();
            if (n > 0) {
                send_bin(buf, static_cast<std::size_t>(n));
            }
        }

        f.close();

        std::string end_json = "{\"type\":\"file_end\"}";
        send_text(end_json);

        beast::flat_buffer buffer;
        if (use_tls_) {
            ws_tls_->read(buffer);
        } else {
            ws_plain_->read(buffer);
        }
        std::string reply = beast::buffers_to_string(buffer.data());
        fprintf(
            stdout, 
            "[WS] Reply for %s: %s\n", file_path.c_str(), reply.c_str()
        );
        return 0;
    } catch (const std::exception& e) {
        fprintf(
            stderr, 
            RED "[WS] send_file exception: %s\n" RESET, e.what()
        );
        connected_ = false;
        return -1;
    }
}

int WsClient::send_end() {
    if (!connected_) return 0;
    try {
        std::string end_json = "{\"type\":\"end\"}";
        if (use_tls_) {
            ws_tls_->text(true);
            ws_tls_->write(net::buffer(end_json));

            beast::flat_buffer buffer;
            ws_tls_->read(buffer);
        } else {
            ws_plain_->text(true);
            ws_plain_->write(net::buffer(end_json));

            beast::flat_buffer buffer;
            ws_plain_->read(buffer);
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(
            stderr, 
            RED "[WS] send_end exception: %s\n" RESET, e.what()
        );
        connected_ = false;
        return -1;
    }
}
