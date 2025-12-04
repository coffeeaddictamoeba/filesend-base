#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <linux/limits.h>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_set>
#include <vector>

#include "defaults.h"
#include "sender.hpp"
#include "db_utils.hpp"
#include "sender_https.hpp"

namespace fs = std::filesystem;

struct batch_t {
    std::size_t size = 1;
    std::vector<std::string> pending;

    bool ready = false;

    explicit batch_t(std::size_t batch_size) : size(batch_size) {
        pending.reserve(size);
    }

    void add(const std::string file_path) {
        if (ready) return;

        pending.emplace_back(std::move(file_path));
        if (size <= 1 || pending.size() >= size) {
            ready = true;
        }
    }

    void clear() {
        pending.clear();
        ready = false;
    }

    bool compress(const std::string& out_path, const std::string& format) const {
        if (pending.empty()) return false;

        fprintf(
            stdout, 
            "[INFO] Batch: compressing %zu files into %s (%s)\n", pending.size(), out_path.c_str(), format.c_str()
        );

        // Ensure parent directory for archive exists
        std::filesystem::path out(out_path);
        if (!out.parent_path().empty()) {
            std::error_code ec;
            std::filesystem::create_directories(out.parent_path(), ec);
            if (ec) {
                fprintf(
                    stderr,
                    RED "[ERROR] Batch: create_directories(%s) failed: %s\n" RESET,
                    out.parent_path().string().c_str(), ec.message().c_str()
                );
                return false;
            }
        }

        auto escape_quotes = [](const std::string& s) {
            std::string r;
            r.reserve(s.size() + 2);
            r.push_back('\'');
            for (char c : s) {
                if (c == '\'') {
                    r.append("'\\''");
                } else {
                    r.push_back(c);
                }
            }
            r.push_back('\'');
            return r;
        };

        std::ostringstream cmd;

        if (format == "tar") {
            cmd << "tar -cf " << escape_quotes(out_path);
            for (const auto& file_path : pending) {
                cmd << " " << escape_quotes(file_path);
            }
        } else if (format == "zip") {
            cmd << "zip -rq " << escape_quotes(out_path);
            for (const auto& file_path : pending) {
                cmd << " " << escape_quotes(file_path);
            }
        } else {
            fprintf(
                stderr, 
                RED "[ERROR] Batch: unsupported format: %s\n" RESET, format.c_str()
            );
            return false;
        }

        std::string cmd_str = cmd.str();

        int rc = std::system(cmd_str.c_str());
        if (rc != 0) {
            fprintf(
                stderr,
                "[ERROR] Batch: compression command failed with code %d\n", rc
            );
            return false;
        }

        return true;
    }
};

class FileSender {
public:
    FileSender(Sender& s, file_db* db = nullptr) : sender_(s), db_(db) {}

    FileSender(Sender& s, batch_t& batch, file_db* db = nullptr) : sender_(s), db_(db), batch_(batch) {}

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
    std::optional<batch_t> batch_;

    bool process_one_file(
        const std::filesystem::path& p,
        std::unordered_set<std::string>& processed
    );

    bool process_one_batch(
        const fs::path& p, 
        std::unordered_set<std::string>& processed,
        int& batch_id
    );
};
