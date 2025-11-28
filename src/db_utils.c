#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/ui_utils.h"
#include "../include/db_utils.h"

int db_resize(db_t* db, int new_size) {
    if (new_size <= db->size) return 0;

    db_entry_t* entry = realloc(db->entries, new_size*sizeof(db_entry_t));
    if (!entry) return -1;
    db->entries = entry;
    for (int i = db->size; i < new_size; ++i) {
        db->entries[i].file_path = NULL;
        db->entries[i].mtime = 0;
        db->entries[i].size = 0;
        db->entries[i].sent_ok = 0;
    }
    db->size = new_size;
    return 0;
}

int db_init(db_t* db, const char* db_path) {
    memset(db, 0, sizeof(*db));

    char dir_buf[PATH_MAX];
    char* res = realpath(db_path, dir_buf);
    if (!res) {
        perror(RED "[DB] realpath" RESET);
        return -1;
    }

    struct stat st;
    if (stat(dir_buf, &st) != 0) {
        perror(RED "[DB] stat" RESET);
        return -1;
    }

    char basedir[PATH_MAX];
    if (S_ISDIR(st.st_mode)) {
        strncpy(basedir, dir_buf, sizeof(basedir)-1);
        basedir[sizeof(basedir)-1] = '\0';
    } else {
        char tmp[PATH_MAX];
        strncpy(tmp, dir_buf, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';

        char* d = dirname(tmp);
        strncpy(basedir, d, sizeof(basedir)-1);
        basedir[sizeof(basedir)-1] = '\0';
    }

    snprintf(
        db->db_path, 
        sizeof(db->db_path)+sizeof(DB_NAME),
        "%s/%s", basedir, DB_NAME
    );

    fprintf(
        stderr, 
        GREEN "[SUCCESS] DB successfully initialized at %s\n" RESET, basedir
    );

    return db_load(db);
}

void db_free(db_t *db) {
    for (int i = 0; i < db->count; ++i) {
        free(db->entries[i].file_path);
    }
    free(db->entries);
    db->entries = NULL;
    db->count = 0;
    db->size = 0;
}

int db_save(db_t *db) {
    FILE* f = fopen(db->db_path, "w");
    if (!f) {
        perror(RED "[DB] fopen save" RESET);
        return -1;
    }

    for (int i = 0; i < db->count; ++i) {
        db_entry_t* entry = &db->entries[i];
        if (!entry->sent_ok || !entry->file_path) continue;
        fprintf(
            f, 
            "%s|%ld|%lld|%d\n",
            entry->file_path,
            (long)entry->mtime,
            (long long)entry->size,
            entry->sent_ok
        );
    }

    fclose(f);
    return 0;
}

int db_load(db_t *db) {
    FILE *f = fopen(db->db_path, "r");
    if (!f) {
        // no DB yet – this is fine
        return 0;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '\n');
        if (p) *p = '\0';

        char* tok_path = strtok(line, "|");
        char* tok_mtime = strtok(NULL, "|");
        char* tok_size = strtok(NULL, "|");
        char* tok_ok = strtok(NULL, "|");

        if (!tok_path || !tok_mtime || !tok_size || !tok_ok) continue;

        if (db_resize(db, db->count + 1) != 0) {
            fclose(f);
            return -1;
        }

        db_entry_t *e = &db->entries[db->count];
        e->file_path = strdup(tok_path);
        e->mtime = (time_t)atol(tok_mtime);
        e->size = (off_t)atoll(tok_size);
        e->sent_ok = atoi(tok_ok);

        db->count++;
    }

    fclose(f);
    return 0;
}

int db_find(db_t* db, const char* file_path) {
    for (int i = 0; i < db->count; ++i) {
        if (db->entries[i].file_path && strcmp(db->entries[i].file_path, file_path) == 0)
            return i;
    }
    return -1;
}

int db_find_sent(db_t* db, const char* file_path) {
    struct stat st;
    if (stat(file_path, &st) != 0) {
        // file disappeared? -> treat as not sent
        return 0;
    }

    int idx = db_find(db, file_path);
    if (idx < 0) return 0;

    db_entry_t* entry = &db->entries[idx];
    if (!entry->sent_ok) return 0;

    if (entry->mtime == st.st_mtime && entry->size == st.st_size) {
        return 1;
    }

    return 0;
}

int db_insert(db_t* db, const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror(RED "[DB] stat in insert" RESET);
        return -1;
    }

    int idx = db_find(db, path);
    if (idx < 0) {
        if (db_resize(db, db->count + 1) != 0) return -1;
        idx = db->count++;
        db->entries[idx].file_path = strdup(path);
    }

    db_entry_t* e = &db->entries[idx];
    e->mtime = st.st_mtime;
    e->size = st.st_size;
    e->sent_ok = 1;

    return db_save(db);
}
