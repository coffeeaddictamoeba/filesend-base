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

struct batch_t {
    std::size_t size = 1;
    std::string format = DEFAULT_COMPRESSION_FORMAT;

    bool ready = false;

    explicit batch_t(std::size_t batch_size) : size(batch_size) {
        pending.reserve(size);
        id = 1;
    }

    explicit batch_t(std::size_t batch_size, std::string& batch_format) : size(batch_size), format(batch_format) {
        pending.reserve(size);
        id = 1;
    }

    void add(std::string_view file_path) {
        if (ready) return;

        pending.emplace_back(file_path);
        if (size <= 1 || pending.size() >= size) {
            ready = true;
        }
    }

    void remove(std::string_view file_path) {
        if (pending.empty()) return;

        pending.erase(
            find(
                pending.begin(), 
                pending.end(), 
                file_path
            )
        );
    }

    void clear() {
        pending.clear();
        ready = false;
    }

    size_t qsize() const { return pending.size(); }

    int get_id() const { return id; }
    void set_id(int new_id) { id = new_id; }

    bool compress(const std::string& out_path, std::string_view format) const {
        if (pending.empty()) return false;

        fprintf(
            stdout, 
            "[INFO] Batch: compressing %zu files into %s (%s)\n", pending.size(), out_path.c_str(), format.data()
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
            return _compress_tar(out_path, (strcmp(format.data(), "tar.gz") == 0));
        } else if (format == "zip") {
            return _compress_zip(out_path);
        } else {
            fprintf(
                stderr, 
                RED "[ERROR] Batch: unsupported format: %s\n" RESET, format.data()
            );
            return false;
        }
    }

private:
    std::vector<std::string> pending;
    int id = 1;

    bool _compress_tar(const std::string& out_path, bool gzipped) const {
        struct archive *a = archive_write_new();
        if (!a) {
            fprintf(
                stderr, 
                RED "[ERROR] archive_write_new() failed\n" RESET
            );
            return false;
        }

        archive_write_set_format_pax_restricted(a);

        int r = gzipped
        ? archive_write_add_filter_gzip(a)
        : archive_write_add_filter_none(a);
        
        if (r != ARCHIVE_OK) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to add filter: %s\n" RESET, archive_error_string(a)
            );
            archive_write_free(a);
            return false;
        }

        r = archive_write_open_filename(a, out_path.c_str());
        if (r != ARCHIVE_OK) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to open output file: %s\n" RESET, archive_error_string(a)
            );
            archive_write_free(a);
            return false;
        }

        fs::path out(out_path);
        std::string batch_dir = out.stem().string();
        if (out.extension() == ".gz") {
            batch_dir = out.stem().stem().string();
        }

        for (const auto& file_path : pending) {
            fs::path p(file_path);

            std::error_code ec;
            auto sz = fs::file_size(p, ec);
            if (ec) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to get size for %s: %s\n" RESET, p.string().c_str(), ec.message().c_str()
                );
                archive_write_free(a);
                return false;
            }

            struct archive_entry *entry = archive_entry_new();
            if (!entry) {
                fprintf(
                    stderr, 
                    RED "[ERROR] archive_entry_new() failed\n" RESET
                );
                archive_write_free(a);
                return false;
            }

            std::string name_in_tar = batch_dir.empty() ? p.filename().string() : (batch_dir + "/" + p.filename().string());

            archive_entry_set_pathname(entry, name_in_tar.c_str());
            archive_entry_set_size(entry, sz);
            archive_entry_set_filetype(entry, AE_IFREG);
            archive_entry_set_perm(entry, 0644);

            r = archive_write_header(a, entry);
            if (r != ARCHIVE_OK) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to write header for %s: %s\n" RESET, p.string().c_str(), archive_error_string(a)
                );
                archive_entry_free(entry);
                archive_write_free(a);
                return false;
            }

            std::ifstream file(p, std::ios::binary);
            if (!file.is_open()) {
                fprintf(
                    stderr,
                    RED "[ERROR] Failed to open file: %s\n" RESET, p.string().c_str()
                );
                archive_entry_free(entry);
                archive_write_free(a);
                return false;
            }

            char buffer[8192];
            while (true) {
                file.read(buffer, sizeof(buffer));
                std::streamsize bytes_read = file.gcount();
                if (bytes_read > 0) {
                    la_ssize_t written = archive_write_data(a, buffer, bytes_read);
                    if (written < 0 || static_cast<std::size_t>(written) != static_cast<std::size_t>(bytes_read)) {
                        fprintf(
                            stderr,
                            RED "[ERROR] Failed to write data for %s: %s\n" RESET,
                            p.string().c_str(), archive_error_string(a)
                        );
                        archive_entry_free(entry);
                        archive_write_free(a);
                        return false;
                    }
                }

                if (file.eof()) break;

                if (file.bad()) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Failed to read file: %s\n" RESET, p.string().c_str()
                    );
                    archive_entry_free(entry);
                    archive_write_free(a);
                    return false;
                }
            }

            archive_entry_free(entry);
        }

        r = archive_write_close(a);
        if (r != ARCHIVE_OK) {
            fprintf(
                stderr, 
                RED "[ERROR] Failed to close tar archive: %s\n" RESET, archive_error_string(a)
            );
            archive_write_free(a);
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
    FileSender(Sender& s, file_db* db = nullptr) : sender_(s), db_(db) {
        batch_ = nullptr; 
    }

    FileSender(Sender& s, batch_t* batch, file_db* db = nullptr) : sender_(s), db_(db), batch_(batch) {}

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
    batch_t* batch_;

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

