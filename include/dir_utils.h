#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <unordered_set>

#include "defaults.h"
#include "sender.hpp"
#include "db_utils.hpp"
#include "sender_https.hpp"

class FileSender {
public:
    FileSender(Sender& s, file_db* db = nullptr) : sender_(s), db_(db){}

    // Send a single file (encrypt + send + no end)
    bool send_one_file(const std::string& file_path);

    // Send a path (file or directory); if directory, monitor new files
    // until no new files appear for 'timeout' seconds. Then send_end().
    bool send_files_from_path(
        const std::string& path, 
        std::chrono::seconds timeout
    );

private:
    Sender& sender_;
    file_db* db_;

    bool process_one_file(
        const std::filesystem::path& p,
        std::unordered_set<std::string>& processed
    );
};
