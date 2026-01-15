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

#ifdef USE_MULTITHREADING
#include "../include/multithreading_utils.h"
#endif

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
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        if (!pattern.empty() && !match_pattern(pattern.c_str(), ent->d_name)) continue;

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

int process_path(const std::string& init, std::string& dest, const std::function<int(const std::string& src, const std::string& dest)>& fn) {
    if (init.find_first_of("*?") != std::string::npos) {
        std::string::size_type slash = init.find_last_of('/');
        std::string src_dir;
        std::string pattern;

        if (slash == std::string::npos) {
            src_dir = ".";
            pattern = init;
        } else {
            src_dir = init.substr(0, slash);
            pattern = init.substr(slash + 1);
        }

        struct stat st{};
        if (stat(src_dir.c_str(), &st) != 0) {
            perror("[ERROR] stat pattern directory");
            return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
            std::fprintf(
                stderr,
                "[ERROR] %s is not a directory\n", src_dir.c_str()
            );
            return -1;
        }

        if (dest.empty() || dest == init) {
            return process_dir(src_dir, src_dir, pattern, fn);
        } else {;
            return process_dir(src_dir, dest, pattern, fn);
        }
    }

    struct stat st{};
    if (stat(init.c_str(), &st) != 0) {
        perror("[ERROR] stat init_path");
        return -1;
    }

    // Single file
    if (S_ISREG(st.st_mode)) {
        dest = dest.empty() ? init : dest;

        struct stat dstst{};
        if (stat(dest.c_str(), &dstst) == 0 && S_ISDIR(dstst.st_mode)) {
            auto pos = init.find_last_of('/');
            dest += "/";
            dest += (pos == std::string::npos) ? init : init.substr(pos + 1);
        }

        return fn(init, dest);
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(
            stderr,
            "[ERROR] %s is neither file nor directory\n", init.c_str()
        );
        return -1;
    }

    const std::string pattern = "";
    return process_dir(init, dest, pattern, fn);
}

bool FileSender::send_one_file(const fs::path& p) {
    if (!fs::exists(p) || !fs::is_regular_file(p)) {
        fprintf(
            stderr, 
            RED "[ERROR] %s is not a regular file\n" RESET, p.c_str()
        );
        return false;
    }

    bool ok = process_one_file(p, nullptr);
    if (ok) sender_.send_end();

    return ok;
}

bool FileSender::process_one_file(const fs::path& p, std::unordered_set<std::string>* processed) {
    const std::string ps = p.string();

    if (processed) {
        if (processed->count(ps)) return true;
        processed->insert(ps);
    }

    bool claimed = false;
    if (db_) {
        if (!db_->try_begin(ps)) {
            fprintf(stdout, "[INFO] DB: Skipping already sent: %s\n", p.c_str());
            return true;
        }
        claimed = true;
    }

    const auto policy = sender_.get_policy();

    fprintf(
        stdout,
        "[INFO] Processing file: %s (encryption policy: %d)\n",
        p.c_str(), policy.enc_p.flags
    );

    std::string f = policy.is_encryption_needed() ? ps + ".enc" : ps;

    if (!encrypt_to_path(policy, ps, f)) {
        fprintf(stderr, RED "[ERROR] Encryption failed for %s\n" RESET, p.c_str());
        if (db_ && claimed) db_->rollback(ps);
        return false;
    }

    if (!sender_.send_file(f)) {
        fprintf(stderr, RED "[ERROR] Failed to send %s\n" RESET, f.c_str());
        if (db_ && claimed) db_->rollback(f);
        return false;
    }

    if (db_ && claimed) { // we can store only one file as they are the same
        if (f == ps) {
            db_->try_begin(f);
            db_->commit(f);
        } else { // we need to store both filenames
            db_->try_begin(f);
            db_->commit(f);
            db_->commit(ps);
        }
    }

    return true;
}

bool FileSender::process_one_batch(const fs::path& p, std::unordered_set<std::string>* processed) {
    if (!batch_->ready) {
        const std::string ps = p.string();

        if (processed) {
            if (processed->count(ps)) return true;
            processed->insert(ps);
        }

        if (db_ && !db_->try_begin(ps)) {
            fprintf(
                stdout, 
                "[INFO] DB: Skipping already sent file in batch: %s\n", ps.c_str()
            );
            return true;
        }

        batch_->add(ps);
    }

    if (!batch_->ready) return true;

    const std::string archive = batch_->get_name_timestamped();
    const auto pending = batch_->get_pending_filenames();

    if (!batch_->compress(archive, batch_->format)) {
        fprintf(stderr, "[ERROR] Batch compress failed\n");

        if (db_) for (const auto& f : pending) db_->rollback(f);

        batch_->clear();
        return false;
    }

    if (!process_one_file(fs::path(archive), nullptr)) {
        fprintf(stderr, "[ERROR] Batch send failed\n");

        if (db_) for (const auto& f : pending) db_->rollback(f);

        batch_->clear();
        return false;
    }

    if (db_) {
        for (const auto& f : pending) {
            if (!db_->commit(f)) {
                fprintf(
                    stderr, 
                    "[WARN] DB commit false for %s\n", f.c_str()
                );
            }
        }
        db_->flush();
    }

    batch_->increment_id();
    batch_->clear();

    return true;
}

bool FileSender::send_files_from_path(const fs::path& p) {
    return send_files_from_path(p, sender_.get_policy().timeout);
}

bool FileSender::send_files_from_path(const fs::path& p, std::chrono::seconds timeout) {
    DbFlushGuard guard(db_);

    if (!fs::exists(p)) {
        fprintf(
            stderr,
            RED "[ERROR] Path %s does not exist\n" RESET, p.c_str()
        );
        return false;
    }

    // Single file mode
    if (fs::is_regular_file(p)) {
        bool ok = process_one_file(p, nullptr);
        if (ok) sender_.send_end();
        return ok;
    }

    // Directory mode
    if (!fs::is_directory(p)) {
        fprintf(
            stderr,
            RED "[ERROR] %s is neither file nor directory\n" RESET, p.c_str()
        );
        return false;
    }

    std::unordered_set<std::string> processed;

    auto last_new = std::chrono::steady_clock::now();
    const auto poll_interval = std::chrono::seconds(1);

    while (true) {
        bool new_in_this_round = false;

        for (auto& entry : fs::directory_iterator(p)) {
            if (!entry.is_regular_file()) continue;

            const fs::path e = entry.path();

            if (processed.count(e)) continue;

            if (batch_ && batch_->size > 1) {
                if (!process_one_batch(e, &processed)) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Warning: failed to process batch %d\n" RESET, batch_->get_id()
                    );
                    continue;
                }
            } else {
                if (!process_one_file(e,  &processed)) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Warning: failed to process %s\n" RESET, e.c_str()
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

                if (db_) db_->flush(); // save all 

                // If DB is NOT needed on server, comment
                if (db_ && !db_->get_path().empty()) {
                    // if (!encrypt_to_path(sender_.get_policy(), db_->get_path())) { // do we need sent DB encryption?
                    //     fprintf(
                    //         stderr,
                    //         RED "[ERROR] DB: Encryption failed for %s\n" RESET, db_->get_path().c_str()
                    //     );
                    //     return false;
                    // }
                    sender_.send_file(db_->get_path());
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

#ifdef USE_MULTITHREADING
static bool is_tmp(const std::string& p) noexcept { // needed to prevent race conditions on tmp files
    if (p.empty() || p[0] == '.') return false;

    constexpr const char* TEMP_EXTS[] = {
        ".tmp",
        ".temp"
        "~",
        ".part",
        ".swp",
    };

    auto s = strlen(p.c_str());
    for (auto ext : TEMP_EXTS) {
        auto e = strlen(ext);
        if (s >= e && p.compare(s-e, e, ext) == 0) return true;
    }

    return false;
}

bool FileSender::send_files_from_path_mt(const fs::path& p, int nthreads = MAX_WORKERS_MT) {
    return send_files_from_path_mt(p, sender_.get_policy().timeout, nthreads);
}

bool FileSender::send_files_from_path_mt(const fs::path& p, std::chrono::seconds timeout, int nthreads = MAX_WORKERS_MT) {
    DbFlushGuard guard(db_);

    nthreads = nthreads ? std::min(nthreads, MAX_WORKERS_MT) : MAX_WORKERS_MT;
    
    printf("[INFO] Running with multithreading available. Current threads number: %d\n", nthreads);

    if (fs::is_regular_file(p)) {
        bool ok = process_one_file(p, nullptr);
        if (ok) sender_.send_end();
        return ok;
    }

    if (!fs::is_directory(p)) {
        fprintf(
            stderr, 
            RED "[ERROR] %s is neither file nor directory\n" RESET, p.c_str()
        );
        return false;
    }

    unordered_set_mt processed;
    TaskQueue<std::string> qe; // to encrypt
    TaskQueue<std::string> qs; // to send

    std::atomic<bool> had_error{false};

    // sender thread
    std::thread sth([&]{
        std::string path;
        while (qs.pop(path)) {
            if (!sender_.send_file(path)) {
                fprintf(stderr, RED "[ERROR] Failed to send %s\n" RESET, path.c_str());
                if (db_) db_->rollback(path);
                had_error = true;
                continue;
            }

            if (db_) db_->commit(path);
        }
    });

    std::vector<std::thread> workers;
    workers.reserve(nthreads);

    for (int i = 0; i < nthreads; ++i) {
        workers.emplace_back([&, i] {
            std::string path;
            while (qe.pop(path)) {
                if (processed.contains(path)) continue;

                bool claimed = false;
                if (db_) {
                    if (!db_->try_begin(path)) {
                        fprintf(stdout, "[INFO] DB: Skipping already sent: %s\n", path.c_str());
                        processed.add(path);
                        continue;
                    }
                    claimed = true;
                }

                const auto policy = sender_.get_policy();

                std::string f = policy.is_encryption_needed() ? path + ".enc" : path;

                try {
                    locked_fd lock(path.c_str(), O_RDONLY);
                    if (!encrypt_to_path_fd(policy, lock.fd, path, f)) {
                        fprintf(stderr, RED "[ERROR] Encryption failed for %s\n" RESET, path.c_str());
                        if (db_ && claimed) db_->rollback(path);
                        had_error = true;
                        processed.add(path);
                        continue;
                    }
                } catch (...) {
                    if (db_) db_->rollback(f);
                    had_error = true;
                    processed.add(f);

                    if (path != f) {
                        if (db_) db_->rollback(path);
                        processed.add(path);
                    }

                    continue;
                }

                if (db_) {
                    db_->try_begin(f);
                    db_->commit(f);
                }

                processed.add(f);
                if (path != f) processed.add(path);

                qs.push(f);
            }
        });
    }

    auto last_new = std::chrono::steady_clock::now();
    const auto poll_interval = std::chrono::seconds(1);

    while (true) {
        bool new_in_this_round = false;

        for (auto& entry : fs::directory_iterator(p)) {
            if (!entry.is_regular_file()) continue;
            const fs::path e = entry.path();
            const std::string es = e.string();

            if (is_tmp(es) || processed.contains(es)) continue;

            if (batch_ && batch_->size > 1) {
                fprintf(
                    stderr, 
                    YELLOW "[WARN] batch is not supported in this path (coming soon)\n" RESET
                );
                continue;
            }

            qe.push(es);
            new_in_this_round = true;
            last_new = std::chrono::steady_clock::now();
        }

        if (timeout.count() > 0 && !new_in_this_round) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_new >= timeout) {
                fprintf(
                    stdout, 
                    YELLOW "[INFO] No new files for %lld seconds, stopping.\n" RESET, (long long)timeout.count()
                );
                break;
            }
        }

        if (timeout.count() <= 0) {
            std::this_thread::sleep_for(poll_interval);
            continue;
        }

        std::this_thread::sleep_for(poll_interval);
    }

    qe.stop();
    for (auto& t : workers) t.join();

    qs.stop();
    sth.join();

    if (db_) db_->flush();

    if (db_ && !db_->get_path().empty()) {
        const std::string dbp = db_->get_path();
        // if (!encrypt_to_path(sender_.get_policy(), dbp)) {
        //     fprintf(
        //         stderr, 
        //         RED "[ERROR] DB: Encryption failed for %s\n" RESET, dbp.c_str()
        //     );
        //     sender_.send_end();
        //     return false;
        // }
        sender_.send_file(dbp);
    }

    sender_.send_end();
    return !had_error.load();
}
#endif