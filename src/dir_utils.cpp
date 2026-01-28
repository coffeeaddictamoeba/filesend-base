#include <cassert>
#include <cstddef>
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

// Sending helpers
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
#ifdef USE_MULTITHREADING
    if (nthreads > 0) {
        assert(nthreads <= MAX_WORKERS_MT);

        fs::create_directories(dc.claimed_dir);
        fs::create_directories(dc.work_dir);
        fs::create_directories(dc.failed_dir);

        workdirs->reserve(nthreads);
        for (int i = 0; i < nthreads; ++i) {
            fs::path d = dc.work_dir / ("tid" + std::to_string(i));
            fs::create_directories(d);
            workdirs->push_back(d);
        }
    }
#endif

    // Essentials (both st and mt)
    fs::create_directories(dc.outbox);
    fs::create_directories(dc.outtmp_dir);
    fs::create_directories(dc.archive);
}

bool FileSender::send_one_file(const fs::path& p) {
    if (!fs::exists(p) || !fs::is_regular_file(p)) {
        fprintf(
            stderr, 
            RED "[ERROR] %s is not a regular file\n" RESET, p.c_str()
        );
        return false;
    }

    const TempDirsConfig dc(p.parent_path());

    bool ok = process_and_send_one_file(p, sender_.get_policy(), dc, nullptr);
    if (ok) sender_.send_end();

    return ok;
}

// Encrypts a single file from dir (no DB interaction)
bool FileSender::process_one_file(const fs::path& in, fs::path& out, const FilesendPolicy& policy, const TempDirsConfig& dc, std::unordered_set<std::string>* processed) {
    fprintf(
        stdout,
        "[INFO] Processing file: %s (encryption policy: %d)\n", in.c_str(), policy.enc_p.flags
    );

    const fs::path name = in.filename();

    out  = dc.outbox / (policy.is_encryption_needed() ? fs::path(name.string() + ".enc") : name);

    if (policy.is_encryption_needed()) {
        if (!encrypt_to_path(policy, in, out)) {
            fprintf(stderr, RED "[ERROR] Encryption failed for %s\n" RESET, out.c_str());
            return false;
        } else {
            fs::remove(in); // remove initial file
        }
    } else {
        fs::copy_file(in, out);
    }

    return true;
}

// Encrypts a single file from dir and sends (saves to DB automatically)
bool FileSender::process_and_send_one_file(const fs::path& in, const FilesendPolicy& policy, const TempDirsConfig& dc, std::unordered_set<std::string>* processed) {
    if (processed) {
        if (processed->count(in)) return true;
        processed->insert(in);
    }
    
    const std::string in_str = in.string();
    if (db_ && !db_->claim(in_str)) {
        fprintf(stdout, "[INFO] DB: Skipping already sent: %s\n", in.c_str());
        return true; // existing file is not an error
    }
    
    fs::path out;
    if (process_one_file(in, out, policy, dc, processed)) {
        const std::string out_str = out.string();

        if (!sender_.send_file(out_str)) {
            fprintf(stderr, RED "[ERROR] Failed to send %s\n" RESET, out_str.c_str());
            if (db_) db_->rollback(out_str);
            return false;
        }

        if (db_) {
            db_->claim(out_str);
            db_->commit(out_str);
            db_->commit(in_str);
        }

        if (policy.is_encryption_with_archive()) rename_successful(out, dc.archive / out.filename());

        return true;
    }

    if (db_) db_->rollback(in);

    return false;
}

// Fill the batch file queue, then compress (no DB interaction)
bool FileSender::process_one_batch(FileBatch& b, const fs::path& in, fs::path& archive, const FilesendPolicy& policy, const TempDirsConfig& dc, std::unordered_set<std::string>* processed, uint32_t tag = 0) {
    (void)policy;

    if (!b.ready) {
        b.add(in.string());
    }

    if (!b.ready) return true;

    archive = dc.outtmp_dir / (b.get_name_timestamped(tag) + ".batch");

    printf("[INFO] Batch %d archive: %s\n", b.get_id(), archive.c_str());

    if (!b.compress(archive, batch_->format)) {
        fprintf(stderr, "[ERROR] Batch compress failed: %s\n", archive.c_str());
        b.clear();
        return false;
    }

    // cleanup input files that were batched
    for (const auto& f : b.get_pending_filenames()) {
        std::error_code ec;
        fs::remove(f, ec);
    }

    return true;
}

// Fill the batch file queue, compress, encrypt and then send (saves to DB automatically)
bool FileSender::process_and_send_one_batch(FileBatch& b, const fs::path& in, const FilesendPolicy& policy, const TempDirsConfig& dc, std::unordered_set<std::string>* processed) {
    if (processed) {
        if (processed->count(in.string())) {
            return true;
        }
        processed->insert(in.string());
    }
    
    // Check if file is present in DB
    if (!in.empty() && db_ && !db_->claim(in.string())) {
        fprintf(stdout, "[INFO] DB: Skipping already sent: %s\n", in.c_str());
        return true; // existing file is not an error
    }
    
    fs::path archive;
    if (process_one_batch(b, in, archive, policy, dc, processed) && b.ready) {

        // Prepare for the next batch
        b.increment_id();
        b.clear();

        if (!process_and_send_one_file(archive, policy, dc, nullptr)) {
            fprintf(stderr, "[ERROR] Batch send failed: %s\n", archive.c_str());
            if (db_) {
                for (const auto& f : b.get_pending_filenames()) {
                    db_->rollback(f);
                }
            }
            b.clear();
            return false;
        }

        if (db_) {
            for (const auto& f : b.get_pending_filenames()) {
                if (!db_->commit(f)) {
                    fprintf(stderr, "[WARN] DB: commit false for %s\n", f.c_str());
                }
            }
            db_->flush();
        }

        if (policy.is_encryption_with_archive()) rename_successful(archive, dc.archive / archive.filename());

        return true;
    }

    return true;
}

bool FileSender::send_files_from_path(const fs::path& p) {
    return send_files_from_path(p, sender_.get_policy().timeout);
}

bool FileSender::send_files_from_path(const fs::path& inbox, std::chrono::seconds timeout) {
    DbFlushGuard guard(db_);

    if (!fs::exists(inbox)) {
        fprintf(stderr, RED "[ERROR] Path %s does not exist\n" RESET, inbox.c_str());
        return false;
    }

    // Single file mode
    if (fs::is_regular_file(inbox)) {
        const TempDirsConfig dc(inbox.parent_path());
        bool ok = process_and_send_one_file(inbox, sender_.get_policy(), dc, nullptr);
        if (ok) sender_.send_end();
        return ok;
    }

    // Directory mode
    if (!fs::is_directory(inbox)) {
        fprintf(stderr, RED "[ERROR] %s is neither file nor directory\n" RESET, inbox.c_str());
        return false;
    }

    const auto policy = sender_.get_policy();
    const TempDirsConfig dc(inbox);
    init_workdirs(0, dc, nullptr); // init only essential dirs

    std::unordered_set<std::string> processed;

    auto last_new = std::chrono::steady_clock::now();
    const auto poll_interval = std::chrono::seconds(1);

    while (true) {
        bool new_in_this_round = false;

        for (auto& entry : fs::directory_iterator(inbox)) {
            if (!entry.is_regular_file()) continue;

            const fs::path e = entry.path();

            if (processed.count(e)) continue;

            if (batch_ && batch_->size > 1) {
                if (!process_and_send_one_batch(*batch_, e, policy, dc, &processed)) {
                    fprintf(
                        stderr,
                        RED "[ERROR] Warning: failed to process batch %d\n" RESET, batch_->get_id()
                    );
                    continue;
                }
            } else {
                if (!process_and_send_one_file(e, policy, dc, &processed)) {
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
            std::this_thread::sleep_for(poll_interval);
            continue;
        }

        if (!new_in_this_round) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_new >= timeout) {

                // Batch
                if (batch_ && batch_->qsize() > 0) {
                    printf(
                        "[INFO] Timeout reached (%lld seconds), sending last batch: %d (queue size: %zu/%zu).\n", 
                        (long long)timeout.count(), batch_->get_id(), batch_->qsize(), batch_->size
                    );

                    batch_->ready = true;

                    fs::path dummy;
                    if (!process_and_send_one_batch(*batch_, dummy, policy, dc,&processed)) {
                        fprintf(
                            stderr,
                            RED "[ERROR] Warning: failed to process last batch %d (queue size: %zu/%zu)\n" RESET, 
                            batch_->get_id(), batch_->qsize(), batch_->size
                        );
                    }

                // Separate files
                } else {
                    printf(YELLOW "[INFO] Timeout reached: No new events for %lld seconds, stopping.\n" RESET, (long long)timeout.count());
                }

                if (db_) {
                    db_->flush(); // save all 
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
bool FileSender::send_files_from_path_mt(const fs::path& p, int nthreads = MAX_WORKERS_MT) {
    return send_files_from_path_mt(p, sender_.get_policy().timeout, nthreads);
}

bool FileSender::send_files_from_path_mt(const fs::path& inbox, std::chrono::seconds timeout, int nthreads = MAX_WORKERS_MT) {
    DbFlushGuard guard(db_);

    if (fs::is_regular_file(inbox)) {
        const TempDirsConfig dc(inbox.parent_path());
        bool ok = process_and_send_one_file(inbox, sender_.get_policy(), dc, nullptr);
        if (ok) sender_.send_end();
        return ok;
    }

    if (!fs::is_directory(inbox)) {
        fprintf(stderr, RED "[ERROR] %s is neither file nor directory\n" RESET, inbox.c_str());
        return false;
    }

    nthreads = nthreads ? std::min(nthreads, MAX_WORKERS_MT) : MAX_WORKERS_MT;
    printf("[INFO] Running with multithreading available. Current threads number: %d\n", nthreads);

    if (nthreads == 1) return send_files_from_path(inbox);

    TempDirsConfig dc(inbox);
    std::vector<fs::path> workdirs;
    init_workdirs(nthreads, dc, &workdirs);

    const auto policy = sender_.get_policy();

    TaskQueue<fs::path> qe; // to encrypt
    TaskQueue<fs::path> qs; // to send

    std::atomic<bool> had_error{false};
    std::atomic<int> inflight{0}; // counts BOTH qe-items and qs-items

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
                if (policy.is_encryption_with_archive()) {
                    rename_successful(enc, dc.archive / enc.filename());
                }
            }

            inflight.fetch_sub(1, std::memory_order_relaxed); // finishes THIS qs-item
        }
    });

    // ---------- workers ----------
    std::vector<std::thread> workers;
    workers.reserve(nthreads);

    std::vector<FileBatch> worker_batches;
    const bool batching = (batch_ && batch_->size > 1);
    if (batching) {
        worker_batches.assign(nthreads, *batch_);
    }

    auto enqueue_send = [&](const fs::path& out) {
        if (out.empty()) return;
        inflight.fetch_add(1, std::memory_order_relaxed); // a NEW qs-item
        qs.push(out);
    };

    for (int i = 0; i < nthreads; ++i) {
        workers.emplace_back([&, i]{
            fs::path claimed;

            auto finish_qe_item = [&] {
                inflight.fetch_sub(1, std::memory_order_relaxed);
            };

            auto mark_failed_and_finish = [&](const fs::path& p) {
                had_error = true;
                if (!rename_successful(p, dc.failed_dir / p.filename())) {
                    std::error_code ec;
                    fs::remove(p, ec);
                }
                finish_qe_item();
            };

            while (qe.pop(claimed)) {
                printf("[INFO] TID %d: Acquired file: %s\n", i, claimed.c_str());

                // Move claimed -> workdir (exclusive)
                fs::path mine = workdirs[i] / claimed.filename();
                if (!rename_successful(claimed, mine)) {
                    // Can't take ownership; just finish qe item
                    finish_qe_item();
                    continue;
                }

                // Batch
                if (batching) {
                    fs::path archive; // produced when batch becomes ready
                    if (!process_one_batch(worker_batches[i], mine, archive, policy, dc, nullptr, (uint32_t)i)) {
                        // process_one_batch already cleared batch; archive may exist
                        if (!archive.empty()) {
                            had_error = true;
                            if (!rename_successful(archive, dc.failed_dir / archive.filename())) {
                                std::error_code ec;
                                fs::remove(archive, ec);
                            }
                        }
                        mark_failed_and_finish(mine);
                        continue;
                    }

                    finish_qe_item();

                    if (archive.empty()) continue;

                    // Batch became ready: archive -> process_one_file -> out -> enqueue send
                    worker_batches[i].increment_id();
                    worker_batches[i].clear();
                    
                    fs::path out;
                    if (!process_one_file(archive, out, policy, dc, nullptr)) {
                        had_error = true;
                        if (!out.empty()) {
                            std::error_code ec;
                            fs::remove(out, ec);
                        }
                        if (!rename_successful(archive, dc.failed_dir / archive.filename())) {
                            std::error_code ec;
                            fs::remove(archive, ec);
                        }
                        continue;
                    }

                    enqueue_send(out);
                    continue;
                }

                // Single-file
                {
                    fs::path out;
                    if (!process_one_file(mine, out, policy, dc, nullptr)) {
                        mark_failed_and_finish(mine);
                        continue;
                    }

                    finish_qe_item();

                    enqueue_send(out);
                }
            }

            // Flush remaining batches
            if (batching) {
                printf("[INFO] TID %d: Sending last batch %d (%zu/%zu)\n", i, worker_batches[i].get_id(), worker_batches[i].qsize(), worker_batches[i].size);
                // If there are leftovers, force finalize once
                if (worker_batches[i].qsize() > 0) {
                    worker_batches[i].ready = true;

                    fs::path archive;
                    fs::path dummy = workdirs[i] / ".flush"; // not used when ready==true

                    bool ok = process_one_batch(worker_batches[i], dummy, archive, policy, dc, nullptr, (uint32_t)i);

                    worker_batches[i].ready = false;

                    if (!ok) {
                        had_error = true;
                        if (!archive.empty()) {
                            if (!rename_successful(archive, dc.failed_dir / archive.filename())) {
                                std::error_code ec;
                                fs::remove(archive, ec);
                            }
                        }
                        return;
                    }

                    if (!archive.empty()) {
                        fs::path out;
                        if (!process_one_file(archive, out, policy, dc, nullptr)) {
                            had_error = true;
                            if (!out.empty()) {
                                std::error_code ec;
                                fs::remove(out, ec);
                            }
                            if (!rename_successful(archive, dc.failed_dir / archive.filename())) {
                                std::error_code ec;
                                fs::remove(archive, ec);
                            }
                            return;
                        }
                        enqueue_send(out);
                    }
                }
            }
        });
    }

    // ---------- recovery & initial ingest ----------
    for (auto& entry : fs::directory_iterator(dc.claimed_dir)) {
        if (!entry.is_regular_file()) continue;
        inflight.fetch_add(1, std::memory_order_relaxed); // qe-item
        qe.push(entry.path());
    }

    for (auto& entry : fs::directory_iterator(dc.outbox)) {
        if (!entry.is_regular_file()) continue;
        const fs::path p = entry.path();

        if (db_) {
            if (!db_->claim(p.string())) {
                fprintf(stdout, "[INFO] DB: Skipping already sent outbox file: %s\n", p.c_str());
                continue;
            }
        }

        inflight.fetch_add(1, std::memory_order_relaxed); // qs-item
        qs.push(p);
    }

    for (auto& entry : fs::directory_iterator(inbox)) {
        if (!entry.is_regular_file()) continue;

        const fs::path e = entry.path();
        const std::string f = e.string();
        const std::string name = e.filename().string();

        if (is_hidden_or_tmp(name)) continue;

        if (db_ && !db_->claim(f)) {
            fprintf(stdout, "[INFO] DB: Skipping already sent/rejected file: %s\n", f.c_str());
            continue;
        }

        const fs::path claimed = dc.claimed_dir / (name + ".c." + tid_unique_suffix(::getpid()));

        if (!rename_successful(e, claimed)) {
            if (db_) db_->rollback(f);
            continue;
        }

        inflight.fetch_add(1, std::memory_order_relaxed);

        qe.push(claimed);
    }

    // ---------- inotify collector ----------
    std::atomic<bool> running{true};
    std::atomic<long long> last_ready_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
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

            if (is_hidden_or_tmp(name)) return;

            if (db_ && !db_->claim(f)) {
                fprintf(stdout, "[INFO] DB: Skipping already sent/rejected file: %s\n", f.c_str());
                return;
            }

            const fs::path claimed = dc.claimed_dir / (name + ".c." + tid_unique_suffix(::getpid()));
            if (!rename_successful(ready_file, claimed)) {
                if (db_) db_->rollback(f);
                return;
            }

            inflight.fetch_add(1, std::memory_order_relaxed); // qe-item
            qe.push(claimed);
        }, running, last_ready_ms);
    });

    // Timeout
    if (timeout.count() > 0) {
        while (true) {
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
            auto last_ms = last_ready_ms.load(std::memory_order_relaxed);

            if ((now_ms - last_ms) >= (timeout.count() * 1000LL) && qe.size() <= 0 && qs.size() <= 0) {
                if (inflight.load(std::memory_order_relaxed) == 0) {
                    printf(YELLOW "[INFO] Timeout reached: No new events for %lld seconds, stopping.\n" RESET, (long long)timeout.count());
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    } else {
        for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Shutdown
    running = false;
    watcher.stop();
    inotify_thr.join();

    qe.stop();
    for (auto& t : workers) t.join();

    // Wait for sender's work
    while (inflight.load(std::memory_order_relaxed) != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    qs.stop();
    sender_thr.join();

    if (db_) {
        db_->flush();
        sender_.send_file(db_->get_path());
    }

    sender_.send_end();
    return !had_error.load();
}
#endif