#include <cstddef>
#include "sender.hpp"

struct filesend_config_t {
    send_policy_t policy;

    std::string mode;          // "send" / "encrypt" / "decrypt"
    std::string init_path;     // file or directory
    std::string dest_path;     // for encrypt/decrypt (file or dir)
    std::string device_id;

    std::size_t batch_size;

    int use_ws;               // 0 = use https, >0 = use websocket
};