#include <cassert>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <fstream>
#include <atomic>
#include <unordered_set>
#include <vector>

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
        if (!db_->claim(ps)) {
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
            db_->claim(f);
            db_->commit(f);
        } else { // we need to store both filenames
            db_->claim(f);
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

        if (db_ && !db_->claim(ps)) {
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
static inline int open_dup_readonly(const fs::path& p) {
    int fd = ::open(p.c_str(), O_RDONLY);
    if (fd < 0) return -1;
    int fd2 = ::dup(fd);
    ::close(fd);
    return fd2;
}

static inline bool rename_successful(const fs::path& a, const fs::path& b) {
    std::error_code ec;
    fs::rename(a, b, ec);
    return !ec;
}

static void init_workdirs(int nthreads, const TempDirsConfig& dc, std::vector<fs::path>* workdirs) {
    assert(nthreads <= MAX_WORKERS_MT);

    fs::create_directories(dc.claimed_dir);
    fs::create_directories(dc.work_dir);
    fs::create_directories(dc.outtmp_dir);
    fs::create_directories(dc.failed_dir);
    fs::create_directories(dc.outbox);
    fs::create_directories(dc.archive);

    workdirs->reserve(nthreads);
    for (int i = 0; i < nthreads; ++i) {
        fs::path d = dc.work_dir / ("tid" + std::to_string(i));
        fs::create_directories(d);
        workdirs->push_back(d);
    }
}

bool FileSender::send_files_from_path_mt(const fs::path& p, int nthreads = MAX_WORKERS_MT) {
    return send_files_from_path_mt(p, sender_.get_policy().timeout, nthreads);
}

bool FileSender::send_files_from_path_mt(const fs::path& inbox, std::chrono::seconds timeout, int nthreads = MAX_WORKERS_MT) {
    DbFlushGuard guard(db_);

    if (fs::is_regular_file(inbox)) {
        bool ok = process_one_file(inbox, nullptr);
        if (ok) sender_.send_end();
        return ok;
    }

    if (!fs::is_directory(inbox)) {
        fprintf(stderr, RED "[ERROR] %s is neither file nor directory\n" RESET, inbox.c_str());
        return false;
    }

    nthreads = nthreads ? std::min(nthreads, MAX_WORKERS_MT) : MAX_WORKERS_MT;
    
    printf("[INFO] Running with multithreading available. Current threads number: %d\n", nthreads);

    TempDirsConfig dc(inbox); std::vector<fs::path> workdirs;
    init_workdirs(nthreads, dc, &workdirs);

    const auto policy = sender_.get_policy();
    bool do_enc = policy.is_encryption_needed();

    TaskQueue<fs::path> qe; // to encrypt
    TaskQueue<fs::path> qs; // to send

    std::atomic<bool> had_error{false};
    std::atomic<int>  inflight{0};        // work items currently being processed

    // ---------- sender thread ----------
    std::thread sender_thr([&]{
        fs::path enc;
        while (qs.pop(enc)) {
            const std::string key = enc.string();
            if (!sender_.send_file(key)) {
                fprintf(stderr, RED "[ERROR] Failed to send %s\n" RESET, key.c_str());
                if (db_) db_->rollback(key);
                had_error = true;
            } else {
                if (db_) db_->commit(key);
                if (policy.is_encryption_with_archive()) rename_successful(enc, dc.archive / enc.filename());
            }
            inflight.fetch_sub(1, std::memory_order_relaxed);
        }
    });

    // ---------- workers ----------
    std::vector<std::thread> workers;
    workers.reserve(nthreads);

    for (int i = 0; i < nthreads; ++i) {
        workers.emplace_back([&, i]{
            fs::path claimed;
            while (qe.pop(claimed)) {

                printf("[INFO] TID %d: Acquired plainfile: %s\n", i, claimed.c_str());

                const std::string suffix = tid_unique_suffix(i);

                // Worker-exclusive claim via rename to its workdir
                fs::path mine = workdirs[i] / (claimed.filename().string() + ".w." + suffix);
                if (!rename_successful(claimed, mine)) {
                    inflight.fetch_sub(1, std::memory_order_relaxed);
                    continue;
                }

                // Recover base name
                std::string base = mine.filename().string();
                auto pos = base.find(".c.");
                if (pos != std::string::npos) base = base.substr(0, pos);
                else {
                    auto posw = base.find(".w.");
                    if (posw != std::string::npos) base = base.substr(0, posw);
                }

                fs::path enc_final = do_enc ? (dc.outbox / (base + ".enc")) : (dc.outbox / base);
                fs::path enc_tmp   = dc.outtmp_dir / (base + ".enc.tmp." + suffix);

                bool ok = true;

                if (do_enc) {
                    int fd2 = open_dup_readonly(mine);
                    if (fd2 < 0) {
                        fprintf(
                            stderr, 
                            RED "[ERROR] open failed %s: %s\n" RESET, mine.c_str(), strerror(errno)
                        );
                        ok = false;
                    } else {
                        ok = encrypt_to_path_fd(
                            policy, 
                            fd2, 
                            mine.string(), 
                            enc_tmp.string()
                        );
                        ::close(fd2);
                    }
                } else {
                    std::error_code ec;
                    fs::copy_file(mine, enc_tmp, ec);
                    ok = !ec;
                }

                auto handle_rename_unsuccessful = [&](const fs::path& p){
                    had_error = true;
                    fs::remove(enc_tmp);
                    if (!rename_successful(p, dc.failed_dir / p.filename())) fs::remove(p);
                    inflight.fetch_sub(1, std::memory_order_relaxed);
                };

                if (!ok) {
                    handle_rename_unsuccessful(mine);
                    continue; 
                }

                // Publish to outbox
                if (fs::exists(enc_final)) {
                    enc_final = dc.outbox / (base + ".dup_" + suffix + ".enc");
                }

                if (!rename_successful(enc_tmp, enc_final)) {
                    handle_rename_unsuccessful(mine);
                    continue;
                }

                fs::remove(mine);

                if (db_ && !db_->claim(enc_final.string())) continue; // commit occurs after successful sending

                qs.push(enc_final); // sender thread will decrement inflight when it sends
            }
        });
    }

    // 1. Already claimed plaintext
    for (auto& entry : fs::directory_iterator(dc.claimed_dir)) {
        if (!entry.is_regular_file()) continue;
        inflight.fetch_add(1, std::memory_order_relaxed);
        qe.push(entry.path());
    }

    // 2. Outbox not sent yet -> enqueue
    for (auto& entry : fs::directory_iterator(dc.outbox)) {
        if (!entry.is_regular_file()) continue;

        const fs::path p = entry.path();
        if (!db_->claim(p)) {
            fprintf(stdout, "[INFO] DB: Skipping already sent file: %s\n", p.c_str());
            continue;
        }

        inflight.fetch_add(1, std::memory_order_relaxed);
        qs.push(p);
    }

    // Claim already-present inbox files
    for (auto& entry : fs::directory_iterator(inbox)) {
        if (!entry.is_regular_file()) continue;

        const fs::path e = entry.path();
        const std::string f = e.string();
        const std::string name = e.filename().string();

        if (is_hidden_or_tmp(name) || (db_ && !db_->claim(f))) {
            fprintf(stdout, "[INFO] DB: Skipping already sent or rejected (temp) file: %s\n", f.c_str());
            continue;
        }

        const fs::path claimed = dc.claimed_dir / (name + ".c." + tid_unique_suffix(::getpid()));

        if (!rename_successful(e, claimed)) {
            if (db_) db_->rollback(e);
            continue;
        }

        inflight.fetch_add(1, std::memory_order_relaxed);

        qe.push(claimed);
    }

    // ---------- inotify collector ----------
    std::atomic<bool> running{true};
    std::atomic<long long> last_ready_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
    };

    InotifyWatcher watcher(inbox);
    if (!watcher.start()) {
        running = false;
        qe.stop();
        for (auto& t : workers) t.join();
        qs.stop();
        sender_thr.join();
        return false;
    }

    std::thread inotify_thr([&]{
        watcher.loop([&](const fs::path& ready_file){
            const std::string f = ready_file.string();
            const std::string name = ready_file.filename().string();

            if (is_hidden_or_tmp(name) || (db_ && !db_->claim(f))) {
                fprintf(stdout, "[INFO] DB: Skipping already sent or rejected (temp) file: %s\n", f.c_str());
                return;
            }

            const fs::path claimed = dc.claimed_dir / (name + ".c." + tid_unique_suffix(::getpid()));
            if (!rename_successful(ready_file, claimed)) {
                if (db_) db_->rollback(name);
                return;
            }

            inflight.fetch_add(1, std::memory_order_relaxed);
            qe.push(claimed);
        }, running, last_ready_ms);
    });

    // Stop if timeout > 0 AND there were no new ready events for timeout AND inflight == 0
    if (timeout.count() > 0) {
        while (true) {
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            auto last_ms = last_ready_ms.load(std::memory_order_relaxed);

            if ((now_ms - last_ms) >= (timeout.count() * 1000LL) && qe.size() <= 0 && qs.size() <= 0) {
                if (inflight.load(std::memory_order_relaxed) == 0) {
                    printf("[INFO] No new events for %lld seconds and queues drained, stopping.\n", (long long)timeout.count());
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    } else {
        for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // ---------- shutdown ----------
    running = false;
    watcher.stop();
    inotify_thr.join();

    qe.stop(); for (auto& t : workers) t.join();
    qs.stop(); sender_thr.join();

    if (db_) {
        db_->flush();
        if (!db_->get_path().empty()) {
            sender_.send_file(db_->get_path());
        }
    }

    sender_.send_end();
    return !had_error.load();
}
#endif