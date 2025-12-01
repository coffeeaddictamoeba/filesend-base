#pragma once

#include <filesystem>
#include <chrono>
#include <unordered_set>

#include "sender.hpp"
#include "db_utils.hpp"

class FileSender {
public:
    FileSender(Sender& s, enc_policy_t enc, retry_policy_t retry, file_db* db = nullptr) : sender_(s), enc_(enc), retry_(retry), db_(db){}

    // Send a single file (encrypt + send + no end)
    bool send_one_file(const std::string& file_path, const std::string& device_id);

    // Send a path (file or directory); if directory, monitor new files
    // until no new files appear for 'timeout' seconds. Then send_end().
    bool send_files_from_path(
        const std::string& path,
        const std::string& device_id,
        std::chrono::seconds timeout
    );

private:
    Sender& sender_;
    enc_policy_t enc_;
    retry_policy_t retry_;
    file_db* db_;

    bool process_one_file(
        const std::filesystem::path& p,
        const std::string& device_id,
        std::unordered_set<std::string>& processed
    );
};
