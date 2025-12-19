#pragma once

#include <cstddef>
#include <istream>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <ctime>
#include <unordered_map>

#include "defaults.h"

class SentFileDatabase {

struct db_entry_t {
    std::string file_path;
    uint64_t mtime;
    uint64_t size;
    bool sent;
};

public:
    explicit SentFileDatabase(const std::string& db_path);

    bool load();
    bool clear();
    bool save() const;

    bool is_sent(const std::string& file_path) const;

    bool insert(const std::string& file_path);
    bool remove(const std::string& file_path);

    const std::string& get_path() const { return db_path_; }

private:
    std::string db_path_;
    std::vector<db_entry_t> entries_;
    std::unordered_map<std::string, size_t> idx_by_path_;

    bool serialize(std::ostream& out, const db_entry_t& e) const; // write a record
    bool deserialize(std::istream& in, db_entry_t& e);            // read a record

    static bool stat_file(
        const std::string& file_path,
        uint64_t& mtime,
        uint64_t& size
    );
};
