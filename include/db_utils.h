#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <time.h>
#include <linux/limits.h>
#include <sys/types.h>

#define DB_NAME ".filesend_cache"

typedef struct {
    char*  file_path;
    time_t mtime;
    off_t  size;
    int    sent_ok;
} db_entry_t;

typedef struct {
    db_entry_t* entries;
    int  count;
    int  size;
    char db_path[PATH_MAX];
} db_t;

int  db_init(db_t* db, const char* file_path);
void db_free(db_t* db);

int db_load(db_t* db);
int db_save(db_t* db);
int db_clean(db_t* db);

int db_find(db_t* db, const char* file_path);
int db_find_sent(db_t* db, const char* file_path);
int db_insert(db_t* db, const char* file_path);
int db_remove(db_t* db, const char* file_path);

#endif