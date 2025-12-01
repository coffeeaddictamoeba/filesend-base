#pragma once

#include <string>
#include <array>
#include <cstdint>
#include <ctime>

#include "defaults.h"

struct db_entry_t {
    std::string file_path;
    std::string sha_hex;
    std::time_t mtime{};
    std::uint64_t size{};
    bool sent_ok{false};
};

class file_db {
public:
    explicit file_db(const std::string& db_path);

    bool load();
    bool save() const;

    bool is_sent(const std::string& file_path) const;
    bool mark_sent(const std::string& file_path);

    const std::string& db_path() const { return db_path_; }

private:
    std::string db_path_;
    std::array<db_entry_t, MAX_SENT_FILES> entries_;

    int find_file(const std::string& file_path) const;

    bool stat_file(
        const std::string& file_path,
        std::time_t& mtime,
        std::uint64_t& size
    ) const;
};
