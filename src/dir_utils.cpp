#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>

#include "../include/dir_utils.h"

namespace fs = std::filesystem;

int process_dir(const std::string& src_dir, std::string& dest_base, const std::string& pattern, const std::function<int(const std::string& src, const std::string& dest)>& fn) {
    bool dest_is_dir = false;
    struct stat dstst{};

    if (stat(dest_base.c_str(), &dstst) == 0) {
        dest_is_dir = S_ISDIR(dstst.st_mode);
    } else {
        if (mkdir(dest_base.c_str(), 0700) == 0) {
            dest_is_dir = true;
        } else {
            dest_base = src_dir;
            dest_is_dir = true;
        }
    }

    DIR* dir = opendir(src_dir.c_str());
    if (!dir) {
        perror("[ERROR] opendir src_dir");
        return -1;
    }

    int ret = 0;
    struct dirent* ent;
    char path_buf[PATH_MAX];

    while ((ent = readdir(dir)) != nullptr) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        if (!pattern.empty() && !match_pattern(pattern.c_str(), ent->d_name)) {
            continue;
        }

        snprintf(
            path_buf, 
            sizeof(path_buf), 
            "%s/%s", src_dir.c_str(), ent->d_name
        );

        struct stat fst{};
        if (stat(path_buf, &fst) != 0) {
            perror("[WARN] stat entry");
            ret = -1;
            continue;
        }

        if (!S_ISREG(fst.st_mode)) continue;

        std::string src = path_buf;
        std::string dest;

        if (dest_is_dir) {
            dest = dest_base + "/" + ent->d_name;
        } else {
            dest = src;
        }

        if (fn(src, dest) != 0) {
            fprintf(
                stderr, 
                "[WARN] Failed to process %s\n", src.c_str()
            );
            ret = -1;
        }
    }

    closedir(dir);
    return ret;
}

bool FileSender::send_one_file(const std::string& file_path) {
    fs::path p(file_path);
    if (!fs::exists(p) || !fs::is_regular_file(p)) {
        fprintf(
            stderr, 
            RED "[ERROR] %s is not a regular file\n" RESET, 
            file_path.c_str()
        );
        return false;
    }

    bool ok = process_one_file(p, nullptr);
    if (ok) sender_.send_end();

    return ok;
}

bool FileSender::process_one_file(const fs::path& p, std::unordered_set<std::string>* processed) {
    const std::string name = p.filename().string();

    if (db_ && ((strcmp(name.c_str(), DB_NAME) == 0) || db_->is_sent(p.string()))) {
        fprintf(
            stdout,
            "[INFO] Skipping already sent file (DB): %s\n", p.c_str()
        );
        if (processed) processed->insert(name);
        return true;
    }

    if (processed && processed->count(name)) {
        return true;
    }

    fprintf(
        stdout, 
        "[INFO] Processing file: %s (encryption policy: %d)\n", p.c_str(), sender_.get_policy().enc_p.flags
    );

    if (!encrypt_in_place(sender_.get_policy(), p.string())) {
        fprintf(
            stderr,
            "[ERROR] Encryption failed for %s\n", p.c_str()
        );
        return false;
    }

    bool sent = sender_.send_file(p.string());
    if (!sent) {
        fprintf(
            stderr,
            "[ERROR] Failed to send %s\n", p.c_str()
        );
        return false;
    }

    if (processed) processed->insert(name);

    if (db_) {
        if (!db_->insert(p.string())) {
            fprintf(
                stderr,
                "[ERROR] Warning: failed to insert %s to DB\n", p.c_str()
            );
        }
    }

    return true;
}

bool FileSender::process_one_batch(const fs::path& p, std::unordered_set<std::string>* processed) {
    const std::string name = p.filename().string();

    if (!batch_->ready) {
        if (db_ && ((strcmp(name.c_str(), DB_NAME) == 0) || db_->is_sent(p.string()))) {
            fprintf(
                stdout,
                "[INFO] Skipping already sent file inside batch (DB): %s\n", p.c_str()
            );
            if (processed) processed->insert(name);
            return true;
        }

        if (processed && processed->count(name)) return true;

        batch_->add(p.string());

        if (processed) processed->insert(name);

        if (db_) {
            if (!db_->insert(p.string())) {
                fprintf(
                    stderr,
                    "[ERROR] DB: failed to insert %s\n", p.c_str()
                );
            }
        }

        fprintf(
            stdout, 
            "[INFO] Batch N%d: adding file %s (queue size: %zu)\n", batch_->get_id(), p.c_str(), batch_->qsize()
        );
    } 
    
    if (batch_->ready) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        std::ostringstream compressed;
        compressed << "batch_" 
                   << std::setw(3) << std::setfill('0') << batch_->get_id() << "_" 
                   << std::put_time(std::localtime(&now), DEFAULT_DATE_FORMAT) << "." 
                   << batch_->format;
        
        std::string compressed_str = compressed.str();
        
        if (!batch_->compress(compressed_str, batch_->format)) {
            fprintf(
                stderr,
                RED "[ERROR] Compression failed in batch %s\n" RESET, compressed_str.c_str()
            );
            batch_->clear();
            return false;
        }

        if (!process_one_file(compressed_str, nullptr)) {
            fprintf(
                stderr,
                RED "[ERROR] Warning: failed to process batch %s\n" RESET, compressed_str.c_str()
            );
            batch_->clear();
            return false;
        }

        fprintf(
            stdout, 
            "[INFO] Sending batch: %s (queue size: %zu/%zu)\n", 
            compressed_str.c_str(), batch_->qsize(), batch_->size
        );

        batch_->set_id(batch_->get_id()+1);
        batch_->clear();
    }
    
    return true;
}

bool FileSender::send_files_from_path(const std::string& path) {
    return send_files_from_path(path, sender_.get_policy().timeout);
}

bool FileSender::send_files_from_path(const std::string& path, std::chrono::seconds timeout) {
    fs::path root(path);

    if (!fs::exists(root)) {
        fprintf(
            stderr,
            RED "[ERROR] Path %s does not exist\n" RESET, path.c_str()
        );
        return false;
    }

    // Single file mode
    if (fs::is_regular_file(root)) {
        bool ok = process_one_file(root, nullptr);
        if (ok) {
            sender_.send_end();
        }
        return ok;
    }

    // Directory mode
    if (!fs::is_directory(root)) {
        fprintf(
            stderr,
            RED "[ERROR] %s is neither file nor directory\n" RESET, path.c_str()
        );
        return false;
    }

    std::unordered_set<std::string> processed;
    auto last_new = std::chrono::steady_clock::now();
    const auto poll_interval = std::chrono::seconds(1);// increases on success, stays on failure (ok?)

    while (true) {
        bool new_in_this_round = false;

        for (auto& entry : fs::directory_iterator(root)) {
            if (!entry.is_regular_file()) continue;

            const fs::path p = entry.path();
            const std::string name = p.filename().string();

            if (processed.count(name)) continue;

            if (batch_ && batch_->size > 1) {
                if (!process_one_batch(p, &processed)) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Warning: failed to process batch %d\n" RESET, batch_->get_id()
                    );
                    continue;
                }
            } else {
                if (!process_one_file(p,  &processed)) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Warning: failed to process %s\n" RESET, p.c_str()
                    );
                    continue;
                }
            }

            new_in_this_round = true;
            last_new = std::chrono::steady_clock::now();
        }

        if (timeout.count() <= 0) {
            // no timeout: just keep polling forever
            std::this_thread::sleep_for(poll_interval);
            continue;
        }

        if (!new_in_this_round) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_new >= timeout) {
                fprintf(
                    stdout,
                    YELLOW "[INFO] No new files for %lld seconds, stopping.\n" RESET, (long long)timeout.count()
                );

                if (batch_ && batch_->qsize() > 0) {
                    
                    printf(
                        "[INFO] Timeout reached, sending last batch: %d (queue size: %zu/%zu).\n", 
                        batch_->get_id(), batch_->qsize(), batch_->size
                    );

                    batch_->ready = true;

                    fs::path dummy;
                    if (!process_one_batch(dummy, &processed)) {
                        fprintf(
                            stderr,
                            RED "[ERROR] Warning: failed to process last batch %d (queue size: %zu/%zu)\n" RESET, 
                            batch_->get_id(), batch_->qsize(), batch_->size
                        );
                    }
                }

                // If DB is NOT needed on server, comment
                if (db_ && !db_->db_path().empty()) {
                    if (!encrypt_in_place(sender_.get_policy(), db_->db_path())) {
                        fprintf(
                            stderr,
                            RED "[ERROR] DB: Encryption failed for %s\n" RESET, db_->db_path().c_str()
                        );
                        return false;
                    }
                    sender_.send_file(db_->db_path());
                }

                sender_.send_end();
                return true;
            }
        }

        std::this_thread::sleep_for(poll_interval);
    }

    sender_.send_end();
    return true;
}