#include "sender.hpp"

struct filesend_config_t {
    send_policy_t policy;

    std::string mode;          // "send" / "encrypt" / "decrypt"
    std::string init_path;     // file or directory
    std::string dest_path;     // for encrypt/decrypt (file or dir)
    std::string device_id;

    int  use_ws;               // 0 = use https, >0 = use websocket
    int  use_batches;          // 0 = one-by-one, >0 = use batches
};