#include <cstdint>
#include <cstdio>

#include "../include/dir_utils.h"

FileBatch::FileBatch(std::size_t batch_size) : size(batch_size) {
    pending.reserve(size);
    id = 1;
}

FileBatch::FileBatch(std::size_t batch_size, std::string& batch_format) : size(batch_size), format(batch_format) {
    pending.reserve(size);
    id = 1;
}

void FileBatch::add(std::string_view file_path) {
    if (ready) return;

    pending.emplace_back(file_path);
    if (size <= 1 || pending.size() >= size) {
        ready = true;
    }
}

void FileBatch::remove(std::string_view file_path) {
    if (pending.empty()) return;

    pending.erase(
        find(
        pending.begin(), 
        pending.end(), 
        file_path
        )
    );
}

void FileBatch::clear() {
    pending.clear();
    ready = false;
}

std::string FileBatch::get_name_timestamped() const {
    std::time_t t = std::time(nullptr);
    std::tm tm{};

#if defined(__unix__) || defined(__APPLE__)
    localtime_r(&t, &tm);
#else
    tm = *std::localtime(&t);
#endif
        
    char ts[64];
    if (std::strftime(ts, sizeof(ts), DEFAULT_DATE_FORMAT, &tm) == 0) return "";

    char out[256];
    snprintf(
        out, 
        sizeof(out), 
        "batch_%03d_%s.%s", id, ts, format.c_str()
    );

    return std::string(out);
}

std::string FileBatch::get_name_timestamped(uint32_t tag) const {
    std::time_t t = std::time(nullptr);
    std::tm tm{};

#if defined(__unix__) || defined(__APPLE__)
    localtime_r(&t, &tm);
#else
    tm = *std::localtime(&t);
#endif
        
    char ts[64];
    if (std::strftime(ts, sizeof(ts), DEFAULT_DATE_FORMAT, &tm) == 0) return "";

    char out[256];
    snprintf(
        out, 
        sizeof(out), 
        "batch_%03d_%s_%03d.%s", id, ts, tag, format.c_str()
    );

    return std::string(out);
}

bool FileBatch::compress(const std::string& out_path, std::string_view format) const {
    if (pending.empty()) return false;

    fprintf(
        stdout, 
        "[INFO] Batch: compressing %zu files into %s (%s)\n", pending.size(), out_path.c_str(), format.data()
    );

    fs::path out(out_path);
    if (!out.parent_path().empty()) {
        std::error_code ec;
        fs::create_directories(out.parent_path(), ec);
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

bool FileBatch::_compress_tar(const std::string& out_path, bool gzipped) const {
    struct archive *a = archive_write_new();
    if (!a) {
        fprintf(
            stderr, 
            RED "[ERROR] archive_write_new() failed\n" RESET
        );
        return false;
    }

    archive_write_set_format_pax_restricted(a);

    int r = gzipped ? archive_write_add_filter_gzip(a) : archive_write_add_filter_none(a);        
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

    if (out.extension() == ".gz") batch_dir = out.stem().stem().string();

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

bool FileBatch::_compress_zip(const std::string& out_path) const {
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