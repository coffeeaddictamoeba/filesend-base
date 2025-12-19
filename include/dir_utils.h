#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <linux/limits.h>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

#include <zip.h>
#include <archive.h>
#include <archive_entry.h>

#include "defaults.h"
#include "sender.hpp"
#include "db_utils.hpp"
#include "sender_https.hpp"

namespace fs = std::filesystem;

class FileBatch {
public:
    std::size_t size = 1;
    std::string format = DEFAULT_COMPRESSION_FORMAT;

    bool ready = false;

    explicit FileBatch(std::size_t batch_size);

    explicit FileBatch(
        std::size_t batch_size, 
        std::string& batch_format
    );

    void add(std::string_view file_path);
    void remove(std::string_view file_path);

    void clear();

    int get_id() const { return id; }
    int increment_id() { return ++id; }

    std::string get_name_timestamped() const;

    size_t qsize() const { return pending.size(); }

    bool compress(
        const std::string& out_path, 
        std::string_view format
    ) const;

private:
    std::vector<std::string> pending;
    int id = 1;

    bool _compress_zip(const std::string& out_path) const;

    bool _compress_tar(
        const std::string& out_path, 
        bool gzipped
    ) const;
};

class FileSender {
public:
    FileSender(Sender& s, SentFileDatabase* db = nullptr) : sender_(s), db_(db) {
        batch_ = nullptr; 
    }

    FileSender(Sender& s, FileBatch* batch, SentFileDatabase* db = nullptr) : sender_(s), db_(db), batch_(batch) {}

    bool send_one_file(const fs::path& p);

    bool send_files_from_path(
        const fs::path& path, 
        std::chrono::seconds timeout
    );

    bool send_files_from_path(const fs::path& path);

private:
    Sender& sender_;
    SentFileDatabase* db_;
    FileBatch* batch_;

    bool process_one_file(
        const fs::path& p,
        std::unordered_set<std::string>* processed
    );

    bool process_one_batch(
        const fs::path& p, 
        std::unordered_set<std::string>* processed
    );
};

int process_dir(
    const std::string& src_dir, 
    std::string& dest_base, 
    const std::string& pattern, 
    const std::function<int(const std::string& src, const std::string& dest)>& fn
);

