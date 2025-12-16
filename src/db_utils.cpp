#include <cstdint>
#include <fstream>
#include <istream>
#include <ostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <cstring>
#include <cstdio>

#include "../include/defaults.h"
#include "../include/db_utils.hpp"

static std::string dirname_of(std::string_view path) {
    if (path.empty()) return ".";
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";

    if (pos == 0) return "/";

    return std::string(path.substr(0, pos));
}

file_db::file_db(const std::string& db_path) {
    db_path_ = dirname_of(db_path);
    db_path_ += '/' ;
    db_path_ += DB_NAME;

    fprintf(
        stderr,
        GREEN "[SUCCESS] DB initialized at %s\n" RESET, db_path_.c_str()
    );
}

bool file_db::serialize(std::ostream& out, const db_entry_t& e) const {
    uint32_t len = e.file_path.size();
    out.write((char*)&len, 4);
    out.write(e.file_path.data(), len);
    out.write((char*)&e.mtime, 8);
    out.write((char*)&e.size, 8);
    uint8_t ok = e.sent ? 1 : 0;
    out.write((char*)&ok, 1);
    return out.good();
}

bool file_db::deserialize(std::istream& in, db_entry_t& e) {
    uint32_t len;
    if (!in.read((char*)&len, 4)) return false;

    e.file_path.resize(len);
    if (!in.read(e.file_path.data(), len)) return false;

    if (!in.read((char*)&e.mtime, 8)) return false;
    if (!in.read((char*)&e.size, 8)) return false;

    uint8_t ok;
    if (!in.read((char*)&ok, 1)) return false;
    e.sent = ok != 0;

    return true;
}

 bool file_db::stat_file(const std::string& file_path, uint64_t& mtime, uint64_t& size) {
    struct stat st;
    if (::stat(file_path.c_str(), &st) != 0) {
        return false;
    }
    mtime = static_cast<std::uint64_t>(st.st_mtime);
    size  = static_cast<std::uint64_t>(st.st_size);
    return true;
}

bool file_db::load() {
    entries_.clear();
    idx_by_path_.clear();
    entries_.reserve(DB_INIT_SIZE);

    std::ifstream in(db_path_, std::ios::binary);
    if (!in.is_open()) {
        return true;
    }

    db_entry_t e;
    while(deserialize(in, e)) {
        idx_by_path_[e.file_path] = entries_.size();
        entries_.push_back(std::move(e));
    }

    return true;
}

bool file_db::save() const {
    std::ofstream out(db_path_, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::perror("[ERROR] fopen save");
        return false;
    }

    for (const auto& e : entries_) {
        if (!serialize(out, e)) return false;
    }

    return true;
}

bool file_db::is_sent(const std::string& file_path) const {
    if (strcmp(file_path.c_str(), db_path().c_str()) == 0) {
        return true; // don't send the DB itself
    }

    auto it = idx_by_path_.find(file_path);
    if (it == idx_by_path_.end()) {
        return false;
    }

    const db_entry_t& e = entries_[it->second];

    if (!e.sent) return false;

    uint64_t mtime, size;
    if (!stat_file(file_path, mtime, size)) {
        fprintf(
            stderr, 
            RED "[ERROR] DB: stat_file %s in is_sent\n", file_path.data()
        );
        return false;
    }

    return (e.mtime == mtime) && (e.size == size);
}

bool file_db::insert(const std::string& file_path) {
    uint64_t mtime, size;
    if (!stat_file(file_path, mtime, size)) {
        fprintf(
            stderr, 
            RED "[ERROR] DB: stat_file %s in insert\n", file_path.data()
        );
        return false;
    }

    auto it = idx_by_path_.find(file_path);
    if (it == idx_by_path_.end()) {
        db_entry_t e;
        e.file_path = file_path;
        e.mtime = mtime;
        e.size = size;
        e.sent = true;

        idx_by_path_[file_path] = entries_.size();
        entries_.push_back(std::move(e));
    } else {
        db_entry_t& e = entries_[it->second];
        e.mtime = mtime;
        e.size = size;
        e.sent = true;
    }

    return save();
}

bool file_db::clear() {
    entries_.clear();
    idx_by_path_.clear();

    std::ofstream out(db_path_, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::perror("[DB] clean: failed to truncate DB file");
        return false;
    }

    return true;
}

bool file_db::remove(const std::string& file_path) {
    auto it = idx_by_path_.find(file_path);
    if (it == idx_by_path_.end()) {
        return false;
    }

    std::size_t idx = it->second;
    std::size_t last_idx = entries_.size() - 1;

    if (idx != last_idx) {
        entries_[idx] = std::move(entries_[last_idx]);
        idx_by_path_[entries_[idx].file_path] = idx;
    }

    entries_.pop_back();
    idx_by_path_.erase(it);

    return save();
}
