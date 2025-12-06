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

struct batch_t {
    std::size_t size = 1;
    std::string format = DEFAULT_COMPRESSION_FORMAT;

    bool ready = false;

    explicit batch_t(std::size_t batch_size) : size(batch_size) {
        pending.reserve(size);
    }

    explicit batch_t(std::size_t batch_size, std::string& batch_format) : size(batch_size), format(batch_format) {
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

    size_t qsize() { return pending.size(); }

    bool compress(const std::string& out_path, const std::string& format) const {
        if (pending.empty()) return false;

        fprintf(
            stdout, 
            "[INFO] Batch: compressing %zu files into %s (%s)\n", pending.size(), out_path.c_str(), format.c_str()
        );

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

        if (format == "tar" || format == "tar.gz") {
            return _compress_tar(out_path, (strcmp(format.c_str(), "tar.gz") == 0));
        } else if (format == "zip") {
            return _compress_zip(out_path);
        } else {
            fprintf(
                stderr, 
                RED "[ERROR] Batch: unsupported format: %s\n" RESET, format.c_str()
            );
            return false;
        }
    }

private:
    std::vector<std::string> pending;

    bool _compress_tar(const std::string& out_path, bool gzipped) const {
        struct archive *a;
        struct archive_entry *entry;
        int r;

        a = archive_write_new();
        if (gzipped) {
            r = archive_write_set_format_pax_restricted(a);
            if (r != ARCHIVE_OK) {
                fprintf(
                    stderr, 
                    RED "[ERROR] Failed to set tar format: %s\n" RESET, archive_error_string(a)
                );
                return false;
            }
            r = archive_write_add_filter_gzip(a);
            if (r != ARCHIVE_OK) {
                fprintf(
                    stderr, 
                    RED "[ERROR] Failed to add gzip filter: %s\n" RESET, archive_error_string(a)
                );
                return false;
            }
        } else {
            r = archive_write_add_filter_none(a);
            if (r != ARCHIVE_OK) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to add filter: %s\n" RESET, archive_error_string(a)
                );
                return false;
            }
        }
        r = archive_write_open_filename(a, out_path.c_str());
        if (r != ARCHIVE_OK) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to open output file: %s\n" RESET, archive_error_string(a)
            );
            return false;
        }

        for (const auto& file_path : pending) {
            entry = archive_entry_new();
            archive_entry_set_pathname(entry, file_path.c_str());
            archive_entry_set_size(entry, std::filesystem::file_size(file_path));
            archive_entry_set_filetype(entry, AE_IFREG);

            r = archive_write_header(a, entry);
            if (r != ARCHIVE_OK) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to write header for %s: %s\n" RESET, file_path.c_str(), archive_error_string(a)
                );
                return false;
            }

            std::ifstream file(file_path, std::ios::binary);
            char buffer[1024];
            while (file) {
                file.read(buffer, sizeof(buffer));
                archive_write_data(a, buffer, file.gcount());
            }

            if (!file) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to read file: %s\n" RESET, file_path.c_str()
                );
                return false;
            }

            archive_entry_free(entry);
        }

        r = archive_write_close(a);
        if (r != ARCHIVE_OK) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to close tar archive: %s\n" RESET, archive_error_string(a)
            );
            return false;
        }

        archive_write_free(a);
        return true;
    }

    bool _compress_zip(const std::string& out_path) const {
        zip_t* zip = zip_open(out_path.c_str(), ZIP_CREATE | ZIP_EXCL, nullptr);
        if (!zip) {
            perror(RED "[ERROR] Failed to create zip archive" RESET);
            return false;
        }

        for (const auto& file_path : pending) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                fprintf(
                    stderr, 
                    RED "[ERROR] Failed to open file for zipping: %s\n" RESET, file_path.c_str()
                );
                zip_close(zip);
                return false;
            }

            zip_source_t* source = zip_source_file(zip, file_path.c_str(), 0, 0);
            if (!source) {
                fprintf(
                    stderr, 
                    RED "[ERROR] Failed to create zip source for %s\n" RESET, file_path.c_str()
                );
                zip_close(zip);
                return false;
            }

            if (zip_file_add(zip, file_path.c_str(), source, ZIP_FL_OVERWRITE) < 0) {
                fprintf(
                    stderr, 
                    RED "[ERROR] Failed to add file to zip: %s\n" RESET, file_path.c_str()
                );
                zip_source_free(source);
                zip_close(zip);
                return false;
            }
        }

        if (zip_close(zip) < 0) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to close zip archive\n" RESET
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

    bool send_files_from_path(const std::string& path);

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
