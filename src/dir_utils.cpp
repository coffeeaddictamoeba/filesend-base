#include <cstring>
#include <iostream>
#include <thread>

#include "../include/dir_utils.h"

namespace fs = std::filesystem;

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

    std::unordered_set<std::string> dummy;
    bool ok = process_one_file(p, dummy);
    if (ok) sender_.send_end();    // Optionally send_end for single file

    return ok;
}

bool FileSender::process_one_file(const fs::path& p, std::unordered_set<std::string>& processed) {
    const std::string name = p.filename().string();

    if (db_ && ((strcmp(name.c_str(), DB_NAME) == 0) || db_->is_sent(p.string()))) {
        fprintf(
            stdout,
            "[INFO] Skipping already sent file (DB): %s\n", p.c_str()
        );
        processed.insert(name);
        return true;
    }

    if (processed.count(name)) {
        return true;
    }

    fprintf(
        stdout, 
        "[INFO] Processing file: %s\n", p.c_str()
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

    processed.insert(name);

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
        bool ok = process_one_file(root, *static_cast<std::unordered_set<std::string>*>(nullptr));
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
    const auto poll_interval = std::chrono::seconds(1);

    while (true) {
        bool new_in_this_round = false;

        for (auto& entry : fs::directory_iterator(root)) {
            if (!entry.is_regular_file()) continue;

            const fs::path p = entry.path();
            const std::string name = p.filename().string();

            if (processed.count(name)) continue;

            if (!process_one_file(p,  processed)) {
                fprintf(
                    stderr,
                    RED "[ERROR] Warning: failed to process %s\n" RESET, p.c_str()
                );
                continue;
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
                    "[INFO] No new files for %lld seconds, stopping.\n", (long long)timeout.count()
                );

                // If DB is NOT needed on server, comment
                if (db_ && !db_->db_path().empty()) {
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