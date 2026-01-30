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
#include <cerrno>

#ifdef USE_MULTITHREADING
#include "../include/multithreading_utils.h"
#endif

#include "../include/defaults.h"
#include "../include/db_utils.hpp"
#include "../include/helpers.h"

SentFileDatabase::SentFileDatabase(const std::string& db_path) {
    db_path_ = dirname_of(db_path);
    db_path_ += '/' ;
    db_path_ += DB_NAME;

    fprintf(
        stderr,
        GREEN "[SUCCESS] DB initialized at %s\n" RESET, db_path_.c_str()
    );
}

bool SentFileDatabase::serialize(std::ostream& out, const DatabaseEntry& e) const {
    uint32_t len = (uint32_t)e.file_path.size();
    write_u32_le(out, len);
    out.write(e.file_path.data(), len);
    write_u64_le(out, e.mtime);
    write_u64_le(out, e.size);

    uint8_t st = (uint8_t)e.state;
    out.write((char*)&st, 1);
    return out.good();
}

bool SentFileDatabase::deserialize(std::istream& in, DatabaseEntry& e) {
    uint32_t len = 0;
    if (!read_u32_le(in, len)) return false;
    if (len > PATH_MAX*8u) return false;

    e.file_path.resize(len);
    if (!in.read(e.file_path.data(), len)) return false;

    if (!read_u64_le(in, e.mtime)) return false;
    if (!read_u64_le(in, e.size))  return false;

    uint8_t st = 0;
    if (!in.read((char*)&st, 1)) return false;

    e.state = st > (uint8_t)DatabaseEntry::state_t::sent
        ? DatabaseEntry::state_t::none
        : (DatabaseEntry::state_t)st;

    return true;
}

 bool SentFileDatabase::stat_file(const std::string& file_path, uint64_t& mtime, uint64_t& size) {
    struct stat st;
    if (::stat(file_path.c_str(), &st) != 0) return false;
    mtime = static_cast<uint64_t>(st.st_mtime);
    size  = static_cast<uint64_t>(st.st_size);
    return true;
}

bool SentFileDatabase::load() {
#ifdef USE_MULTITHREADING
    std::lock_guard<std::mutex> lk(mu_);
#endif
    entries_.clear();
    idx_by_path_.clear();
    entries_.reserve(DB_INIT_SIZE);
    dirty_ = false;

    std::ifstream in(db_path_, std::ios::binary);
    if (!in.is_open()) return true; // no db yet

    DatabaseEntry e;
    while(deserialize(in, e)) {
        idx_by_path_[e.file_path] = entries_.size();
        entries_.push_back(std::move(e));
    }

    return true;
}

DatabaseEntry& SentFileDatabase::get_or_create_(const std::string& path) {
    auto it = idx_by_path_.find(path);
    if (it != idx_by_path_.end()) {
        return entries_[it->second];
    }

    DatabaseEntry e;
    e.file_path = path;
    e.mtime = 0;
    e.size  = 0;
    e.state = DatabaseEntry::state_t::none;

    idx_by_path_[path] = entries_.size();
    entries_.push_back(std::move(e));
    dirty_ = true;
    return entries_.back();
}

bool SentFileDatabase::ensure_up_to_date_(DatabaseEntry& e, uint64_t mtime, uint64_t size) {
    if (e.mtime == mtime && e.size == size) return true;

    if (e.state == DatabaseEntry::state_t::inflight) {
        e.mtime = mtime;
        e.size  = size;
        dirty_ = true;
        return true;
    }

    // file changed -> treat as new
    e.mtime = mtime;
    e.size  = size;
    dirty_ = true;

    return true;
}

bool SentFileDatabase::claim(const std::string& path) {
    if (path == get_path()) return false;

#ifdef USE_MULTITHREADING
    std::lock_guard<std::mutex> lk(mu_);
#endif

    uint64_t mtime = 0, size = 0;
    if (!stat_file(path, mtime, size)) return false;

    DatabaseEntry& e = get_or_create_(path);

    if (e.state == DatabaseEntry::state_t::sent && e.mtime == mtime && e.size == size) return false;
    if (e.state == DatabaseEntry::state_t::inflight) return false;

    // claim
    e.mtime = mtime;
    e.size  = size;
    e.state = DatabaseEntry::state_t::inflight;
    dirty_ = true;

    return true;
}

bool SentFileDatabase::commit(const std::string& path) {
#ifdef USE_MULTITHREADING
    std::lock_guard<std::mutex> lk(mu_);
#endif
    DatabaseEntry& e = get_or_create_(path);
    if (e.state != DatabaseEntry::state_t::inflight) return false;

    uint64_t mtime = 0, size = 0;
    if (stat_file(path, mtime, size)) {
        e.mtime = mtime;
        e.size  = size;
    }
    e.state = DatabaseEntry::state_t::sent;
    dirty_ = true;

    return true;
}

void SentFileDatabase::rollback(const std::string& path) {
#ifdef USE_MULTITHREADING
    std::lock_guard<std::mutex> lk(mu_);
#endif
    auto it = idx_by_path_.find(path);
    if (it == idx_by_path_.end()) return;

    DatabaseEntry& e = entries_[it->second];
    if (e.state == DatabaseEntry::state_t::inflight) {
        e.state = DatabaseEntry::state_t::none;
        dirty_ = true;
    }
}

bool SentFileDatabase::flush() {
#ifdef USE_MULTITHREADING
    std::lock_guard<std::mutex> lk(mu_);
#endif
    if (!dirty_) return true;

    // write to temp file then rename -> atomic update
    std::string tmp = db_path_ + ".tmp";

    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::perror("[ERROR] DB flush: fopen tmp");
        return false;
    }

    for (const auto& e : entries_) {
        if (!serialize(out, e)) {
            fprintf(stderr, "[ERROR] DB flush: serialize failed\n");
            return false;
        }
    }

    if (::rename(tmp.c_str(), db_path_.c_str()) != 0) {
        std::perror("[ERROR] DB flush: rename");
        // try cleanup
        ::unlink(tmp.c_str());
        return false;
    }

    dirty_ = false;
    return true;
}
