#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "defaults.h"

#if FILESEND_ENABLE_MT
#include "multithreading_utils.h"
#endif

struct NoDatabase {
    static constexpr const char* db_path_ = "";

    explicit NoDatabase(const std::string& db_path) { 
        (void)db_path;
        fprintf(
            stderr, 
            YELLOW "[WARN] The program was compiled without deduplication database support."
            " To enable it, compile with -DFILESEND_PROFILE_FULL\n" RESET
        );
    };

    bool load() { return true; };

    bool claim(const std::string& path)  { (void)path; return true; };
    bool commit(const std::string& path) { (void)path; return true; };
    void rollback(const std::string& path) { (void)path; };
    bool flush() { return true; };

    const std::string& get_path() const { return db_path_; }
};

struct DatabaseEntry {
    std::string file_path;
    uint64_t mtime = 0;
    uint64_t size  = 0;

    enum class state_t : uint8_t {
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

    bool claim(const std::string& path);
    bool commit(const std::string& path);
    void rollback(const std::string& path);
    bool flush();

    const std::string& get_path() const { return db_path_; }

private:
    bool serialize(
        std::ostream& out,
        const DatabaseEntry& e
    ) const;

    bool deserialize(
        std::istream& in,
        DatabaseEntry& e
    );

    static bool stat_file(
        const std::string& file_path,
        uint64_t& mtime,
        uint64_t& size
    );

    DatabaseEntry& get_or_create_(const std::string& path);

    bool ensure_up_to_date_(
        DatabaseEntry& e,
        uint64_t mtime,
        uint64_t size
    );

private:
    std::string db_path_;
    std::vector<DatabaseEntry> entries_;
    std::unordered_map<std::string, std::size_t> idx_by_path_;
    bool dirty_ = false;

#if FILESEND_ENABLE_MT
    mutable std::mutex mu_;
#endif
};

#if FILESEND_ENABLE_DB
  using FileDatabase = SentFileDatabase;
#else
  using FileDatabase = NoDatabase;
#endif

struct DbFlushGuard {
    FileDatabase* db = nullptr;

    explicit DbFlushGuard(FileDatabase* p) : db(p) {}

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
