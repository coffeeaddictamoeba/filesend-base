#include <filesystem>
#include <fstream>
#include <sstream>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <cstring>
#include <cstdio>

#include "../include/defaults.h"
#include "../include/file_utils.h"
#include "../include/db_utils.hpp"

namespace fs = std::filesystem;

int files_total = 0;

std::string dirname_of(const std::string& path) {
    fs::path p(path);
    if (fs::is_directory(p)) return fs::canonical(p).string();
    auto parent = p.parent_path();
    if (parent.empty()) parent = ".";
    return fs::canonical(parent).string();
}

file_db::file_db(const std::string& db_path) {
    std::string base_dir = dirname_of(db_path);
    db_path_ = (fs::path(base_dir) / DB_NAME).string();

    fprintf(
        stderr,
        GREEN "[SUCCESS] DB initialized at %s\n" RESET, db_path_.c_str()
    );
}

int file_db::find_file(const std::string& file_path) const {
    auto it = idx_by_path_.find(file_path);
    if (it == idx_by_path_.end()) return -1;
    return static_cast<int>(it->second);
}

bool file_db::stat_file(const std::string& file_path, std::time_t& mtime, std::uint64_t& size) const {
    struct stat st{};
    if (stat(file_path.c_str(), &st) != 0) {
        return false;
    }
    mtime = st.st_mtime;
    size  = static_cast<std::uint64_t>(st.st_size);
    return true;
}

bool file_db::load() {
    std::ifstream in(db_path_);
    if (!in.is_open()) {
        return true;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string path, mtime_str, size_str, ok_str, sha_str;

        if (!std::getline(iss, path, '|')) continue;
        if (!std::getline(iss, mtime_str, '|')) continue;
        if (!std::getline(iss, size_str, '|')) continue;
        if (!std::getline(iss, ok_str, '|')) continue;
        if (!std::getline(iss, sha_str, '|')) {
            sha_str.clear();
        }

        db_entry_t e;
        e.file_path = path;
        e.mtime     = static_cast<std::time_t>(std::stol(mtime_str));
        e.size      = static_cast<std::uint64_t>(std::stoll(size_str));
        e.sent_ok   = (std::stoi(ok_str) != 0);
        e.sha_hex   = sha_str;

        int idx = files_total++;
        entries_[idx] = std::move(e);
        idx_by_path_[entries_[idx].file_path] = idx;
    }

    return true;
}

bool file_db::save() const {
    std::ofstream out(db_path_, std::ios::trunc);
    if (!out.is_open()) {
        std::perror("[ERROR] fopen save");
        return false;
    }

    for (const auto& e : entries_) {
        if (!e.sent_ok || e.file_path.empty()) continue;
        out << e.file_path << '|'
            << static_cast<long>(e.mtime) << '|'
            << static_cast<long long>(e.size) << '|'
            << (e.sent_ok ? 1 : 0) << '|'
            << (e.sha_hex.empty() ? "" : e.sha_hex)
            << '\n';
    }

    return true;
}

bool file_db::is_sent(const std::string& file_path) const {
    std::time_t mtime{};
    std::uint64_t size{};
    if (!stat_file(file_path, mtime, size)) {
        return false;
    }

    int idx = find_file(file_path);
    if (idx < 0) return false;

    const auto& e = entries_[idx];
    if (!e.sent_ok) return false;

    if (e.mtime != mtime || e.size != size) {
        return false;
    }

    return true;
}

bool file_db::mark_sent(const std::string& file_path) {
    std::time_t mtime{};
    std::uint64_t size{};
    if (!stat_file(file_path, mtime, size)) {
        std::perror("[ERROR] stat in mark_sent");
        return false;
    }

    char sha[crypto_hash_sha256_BYTES * 2 + 1];
    if (compute_file_sha256_hex(file_path.c_str(), sha, sizeof(sha)) != 0) {
        fprintf(
            stderr, 
            "[DB] Failed to compute SHA for %s\n", file_path.c_str()
        );
        return false;
    }

    int idx = find_file(file_path);
    if (idx < 0) {
        db_entry_t e;
        e.file_path  = file_path;
        e.mtime      = mtime;
        e.size       = size;
        e.sent_ok    = true;
        e.sha_hex    = std::move(sha);
        entries_[files_total++] = std::move(e);
    } else {
        auto& e = entries_[idx];
        e.mtime   = mtime;
        e.size    = size;
        e.sent_ok = true;
        e.sha_hex = std::move(sha);
    }

    return save();
}