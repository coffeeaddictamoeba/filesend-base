#include <iostream>
#include <thread>

#include "../include/dir_utils.h"

namespace fs = std::filesystem;

bool FileSender::send_one_file(const std::string& file_path, const std::string& device_id) {
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
    bool ok = process_one_file(p, device_id, dummy);
    if (ok) sender_.send_end(device_id);    // Optionally send_end for single file

    return ok;
}

bool FileSender::process_one_file(const fs::path& p, const std::string& device_id, std::unordered_set<std::string>& processed) {
    const std::string name = p.filename().string();

    if (db_ && db_->is_sent(p.string())) {
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

    if (!encrypt_in_place(enc_, p.string())) {
        fprintf(
            stderr,
            "[ERROR] Encryption failed for %s\n", p.c_str()
        );
        return false;
    }

    bool sent = sender_.send_file(p.string(), device_id, enc_.flags);
    if (!sent) {
        fprintf(
            stderr,
            "[ERROR] Failed to send %s\n", p.c_str()
        );
        return false;
    }

    processed.insert(name);

    if (db_) {
        if (!db_->mark_sent(p.string())) {
            fprintf(
                stderr,
                "[FileSender] Warning: failed to DB-mark %s as sent\n", p.c_str()
            );
        }
    }

    return true;
}


bool FileSender::send_files_from_path(const std::string& path, const std::string& device_id, std::chrono::seconds timeout) {
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
        bool ok = process_one_file(root, device_id, *static_cast<std::unordered_set<std::string>*>(nullptr));
        if (ok) {
            sender_.send_end(device_id);
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

            if (!process_one_file(p, device_id, processed)) {
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
                break;
            }
        }

        std::this_thread::sleep_for(poll_interval);
    }

    sender_.send_end(device_id);
    return true;
}