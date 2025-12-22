#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "defaults.h"

#ifdef USE_MULTITHREADING
#include "multithreading_utils.h"
#endif

struct db_entry_t {
    std::string file_path;
    uint64_t mtime = 0;
    uint64_t size  = 0;

    enum class state_t : std::uint8_t {
        none = 0,
        inflight = 1,
        sent = 2
    };   

    state_t state = state_t::none;
};

class SentFileDatabase {
public:
    explicit SentFileDatabase(const std::string& db_path);

    bool load();

    bool try_begin(const std::string& path);
    bool commit(const std::string& path);
    void rollback(const std::string& path);
    bool flush();

    const std::string& get_path() const { return db_path_; }

private:
    bool serialize(
        std::ostream& out,
        const db_entry_t& e
    ) const;

    bool deserialize(
        std::istream& in,
        db_entry_t& e
    );

    static bool stat_file(
        const std::string& file_path,
        std::uint64_t& mtime,
        std::uint64_t& size
    );

    db_entry_t& get_or_create_(const std::string& path);

    bool ensure_up_to_date_(
        db_entry_t& e,
        std::uint64_t mtime,
        std::uint64_t size
    );

private:
    std::string db_path_;
    std::vector<db_entry_t> entries_;
    std::unordered_map<std::string, std::size_t> idx_by_path_;
    bool dirty_ = false;

#ifdef USE_MULTITHREADING
    mutable std::mutex mu_;
#endif
};

struct DbFlushGuard {
    SentFileDatabase* db = nullptr;

    explicit DbFlushGuard(SentFileDatabase* p) : db(p) {}

    ~DbFlushGuard() {
        if (!db) return;
        if (!db->flush()) {
            fprintf(
                stderr, 
                RED "[ERROR] DB flush failed in guard destructor\n" RESET
            );
        }
    }
};
