#ifndef MULTITHREADING_H
#define MULTITHREADING_H

#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <sys/inotify.h>
#include <system_error>
#include <unistd.h>
#include <fcntl.h>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <cstddef>
#include <unordered_set>
#include <utility>
#include <mutex>
#include <thread>
#include <filesystem>

#include "defaults.h"

#define MAX_WORKERS_MT 4

namespace fs = std::filesystem;

constexpr const char* SPOOL_CLAIMED_DIR = "claimed";
constexpr const char* SPOOL_WORK_DIR = "work";
constexpr const char* SPOOL_FAILED_DIR = "failed";

constexpr const char* INBOX_SPOOL_DIR = ".filesend_spool";

constexpr const char* SPOOL_TEMPDIR_NAMES[] = {
    SPOOL_CLAIMED_DIR,
    SPOOL_FAILED_DIR,
    SPOOL_WORK_DIR
};

class unordered_set_mt {
public:
    bool contains(const std::string& s) {
        std::lock_guard<std::mutex> lk(m_);
        return set_.count(s) != 0;
    }
    void add(const std::string& s) {
        std::lock_guard<std::mutex> lk(m_);
        set_.insert(s);
    }
    bool empty() const { return set_.empty(); }

private:
    std::mutex m_;
    std::unordered_set<std::string> set_;
};

template <typename T>
class TaskQueue {
public:
    void push(T v) {
        std::lock_guard<std::mutex> lk(m_);
        q_.push_back(std::move(v));
        cv_.notify_one();
    }

    bool pop(T& out) {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&]{ return stop_ || !q_.empty(); });

        if (q_.empty()) return false;

        out = std::move(q_.front());
        q_.pop_front();

        return true;
    }

    void stop() {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
        cv_.notify_all();
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_);
        return q_.size();
    }

private:
    mutable std::mutex m_;
    std::condition_variable cv_;
    std::deque<T> q_;
    bool stop_ = false;
};

class InotifyWatcher {
    public:
        explicit InotifyWatcher(const std::string inbox_dir) : inbox_(std::move(inbox_dir)) {}

        bool start() {
            ifd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (ifd_ < 0) {
                fprintf(
                    stderr, 
                    "[ERROR] inotify_init1: %s\n", strerror(errno)
                );
                return false;
            }

            uint32_t mask = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO;
            wd_ = ::inotify_add_watch(ifd_, inbox_.c_str(), mask);
            if (wd_ < 0) {
                fprintf(
                    stderr, 
                    "[ERROR] inotify_add_watch(%s): %s\n", inbox_.c_str(), strerror(errno)
                );
                ::close(ifd_);
                ifd_ = -1;
                return false;
            }

            return true;
        }

        void stop() {
            if (ifd_ >= 0) {
                if (wd_ >= 0) ::inotify_rm_watch(ifd_, wd_);
                ::close(ifd_);
            }
            ifd_ = -1;
            wd_  = -1;
        }

        template<class ReadyFn>
        void loop(ReadyFn on_ready, std::atomic<bool>& running, std::atomic<long long>& last_activity_ms) {
            alignas(inotify_event) char buf[64*1024];

            while (running.load(std::memory_order_relaxed)) {
                ssize_t n = ::read(ifd_, buf, sizeof(buf));
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    fprintf(stderr, "[ERROR] inotify read: %s\n", strerror(errno));
                    break;
                }

                if (n == 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }

                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                last_activity_ms.store(now_ms, std::memory_order_relaxed);

                size_t off = 0;
                while (off < (size_t)n) {
                    auto* ev = reinterpret_cast<inotify_event*>(buf + off);
                    off += sizeof(inotify_event) + ev->len;

                    if (ev->len == 0 || is_hidden_or_tmp(ev->name)) continue;

                    std::string name(ev->name);

                    if (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
                        fs::path f = inbox_ / name;
                        std::error_code ec;
                        if (!fs::is_regular_file(f, ec)) continue;

                        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        last_activity_ms.store(now_ms, std::memory_order_relaxed);

                        on_ready(f);
                    }
                }
            }
        }

    private:
        fs::path inbox_;
        int ifd_ = -1;
        int wd_  = -1;
};

static inline std::string tid_unique_suffix(uint32_t tidx) {
    thread_local uint32_t local_ctr = 0;
    uint32_t c = ++local_ctr;

    char buf[32];
    char* p = buf;
    *p++ = 't';

    auto r1 = std::to_chars(p, buf + sizeof(buf), tidx);
    p = r1.ptr;
    *p++ = '_';

    static constexpr char hex[] = "0123456789abcdef";
    for (int k = 7; k >= 0; --k) *p++ = hex[(c >> (k*4)) & 0xF];

    return std::string(buf, p);
}

#endif // MULTITHREADING_H