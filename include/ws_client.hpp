#pragma once

#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>

namespace net   = boost::asio;
namespace ssl   = boost::asio::ssl;
namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
using tcp = boost::asio::ip::tcp;

class WsClient {
public:
    WsClient(
        const std::string& url,
        const std::string& device_id,
        const std::string& ca_cert = ""
    );

    ~WsClient();

    int connect();
    void close();

    int send_file(const std::string& file_path, int max_attempts, uint32_t flags);
    int send_end();

private:
    std::string url_;
    std::string host_;
    std::string port_str_;
    std::string target_;
    std::string device_id_;
    std::string ca_cert_;
    bool use_tls_{false};

    net::io_context ioc_;
    ssl::context ssl_ctx_;
    tcp::resolver resolver_;

    std::unique_ptr<websocket::stream<tcp::socket>> ws_plain_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> ws_tls_;

    bool connected_{false};

    void parse_url();
    int connect_plain();
    int connect_tls();
    bool is_plain() const { return !use_tls_; }

    websocket::stream<tcp::socket>* ws_plain() { return ws_plain_.get(); }
    websocket::stream<ssl::stream<tcp::socket>>* ws_tls() { return ws_tls_.get(); }
};