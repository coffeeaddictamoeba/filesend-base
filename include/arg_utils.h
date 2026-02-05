#include <cstddef>

#include "helpers.h"
#include "sender.hpp"
#include "config_utils.h"

class ArgParser {
public:
    explicit ArgParser();

    void usage(const char* prog) const;

    int parse(int argc, char** argv);

    FilesendConfig get_config() const { return config_; }

private:
    void init_config();
    void init_config_cli();
    void init_config_ini();

    void handle_send(int argc, char** argv);
    void handle_encrypt(int argc, char** argv);
    void handle_decrypt(int argc, char** argv);
    void handle_verify(int argc, char** argv);

    // General handlers
    void handle_mode_timeout(int& value, int argc, char** argv);
    void handle_mode_dest(int& value, int argc, char** argv);

    // Send arg handlers
    void handle_send_encrypt(int& value, int argc, char** argv);
    void handle_send_batch(int& value, int argc, char** argv);
    void handle_send_retry(int& value, int argc, char** argv);
    void handle_mode_threads(int& value, int argc, char** argv);

    // Security arg handlers
    void handle_key_mode(const char* flag, const char* mode);
    void handle_security_settings(int argc, char** argv);

private:
    FilesendConfig config_;
    std::unordered_map<std::string, std::function<void(int, char**)>> mode_handlers_;
    int argc_;
};