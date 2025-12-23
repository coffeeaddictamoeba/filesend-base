#ifndef MULTITHREADING_H
#define MULTITHREADING_H

#include <condition_variable>
#include <deque>
#include <atomic>
#include <cstddef>
#include <functional>
#include <queue>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include <mutex>
#include <thread>
#include <limits>

#define MAX_WORKERS_MT 4

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
    bool empty() { return set_.empty(); }
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

#endif // MULTITHREADING_H