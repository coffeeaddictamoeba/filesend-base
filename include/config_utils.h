#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "sender.hpp"

struct FilesendConfig {
    FilesendPolicy policy;

    std::string mode;          // "send" / "encrypt" / "decrypt" / "verify"
    std::string init_path;     // file or directory
    std::string dest_path;
    std::string device_id;
    
    std::string batch_format;
    std::size_t batch_size;

#ifdef USE_MULTITHREADING
    int nthreads;
#endif

    bool use_ws = false;
    bool use_config = true;
    bool security_info = true;
};

class GlobalFilesendConfig {
    FilesendConfig cfg;
    std::string cfg_path;

    private:
        bool read(std::string& out);

        void set(
            std::string_view section, 
            std::string_view key, 
            std::string_view val
        );

    public:
        explicit GlobalFilesendConfig(std::string_view path) {
            cfg_path.assign(path.data(), path.size());
        }

        FilesendConfig load();
};