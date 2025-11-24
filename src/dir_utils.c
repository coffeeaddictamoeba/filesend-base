#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../include/dir_utils.h"
#include "../include/send_utils.h"

int is_processed(processed_node_t *head, const char *name) {
    for (processed_node_t *p = head; p; p = p->next) {
        if (strcmp(p->name, name) == 0) return 1;
    }
    return 0;
}

void mark_processed(processed_node_t **head, const char *name) {
    processed_node_t *node = (processed_node_t *)malloc(sizeof(*node));
    if (!node) return;
    node->name = strdup(name);
    node->next = *head;
    *head = node;
}

void free_processed(processed_node_t *head) {
    while (head) {
        processed_node_t *n = head->next;
        free(head->name);
        free(head);
        head = n;
    }
}

// Generic path handler: if file -> call callback once,
// if dir -> process files, and (if timeout > 0) monitor until no new files appear.
int monitor_path(const char* p, int timeout_secs, file_cb_t cb, void* ctx) {
    struct stat st;
    if (stat(p, &st) != 0) {
        perror("[ERROR] stat");
        return -1;
    }

    // Single file: just process and return
    if (S_ISREG(st.st_mode)) return cb(p, ctx);

    // Directory: process files with monitoring
    if (!S_ISDIR(st.st_mode)) {
        fprintf(
            stderr,
            "[ERROR] %s is neither file nor directory\n", p
        );
        return -1;
    }

    processed_node_t *processed = NULL;
    time_t last_new = time(NULL);
    int timeout = timeout_secs;
    int ret = 0;

    for (;;) {
        int new_in_this_round = 0;
        DIR *dir = opendir(p);
        if (!dir) {
            perror("[ERROR] opendir");
            ret = -1;
            break;
        }

        struct dirent *ent;
        char path_buf[PATH_MAX];

        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".")  == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }

            snprintf(path_buf, sizeof(path_buf), "%s/%s", p, ent->d_name);

            struct stat fst;
            if (stat(path_buf, &fst) != 0) {
                perror("[WARN] stat entry");
                ret = -1;
                continue;
            }

            if (!S_ISREG(fst.st_mode)) continue; // skip non-regular

            if (is_processed(processed, ent->d_name)) continue;

            fprintf(
                stdout, 
                "[INFO] Processing file: %s\n", path_buf
            );

            int r = cb(path_buf, ctx);
            mark_processed(&processed, ent->d_name);
            new_in_this_round = 1;
            last_new = time(NULL);

            if (r != 0) {
                fprintf(
                    stderr,
                    "[WARN] Failed to process %s\n", path_buf
                );
                ret = -1;
            }
        }

        closedir(dir);

        if (timeout <= 0) break;

        time_t now = time(NULL);
        if (!new_in_this_round && (now - last_new) >= timeout) {
            fprintf(
                stdout,
                "[INFO] No new files for %d seconds, stopping.\n", timeout
            );
            break;
        }

        sleep(1); // polling interval
    }

    free_processed(processed);
    return ret;
}

int send_file_callback(const char *file_path, void *ctx_void) {
    send_ctx_t *ctx = (send_ctx_t*)ctx_void;
    key_mode_config_t *cf = ctx->cf;

    if (!cf->use_ws) {
        if (!cf->key_mode) return send_file_via_https(ctx->curl, cf->url, file_path, cf->cert_path);

        // key_mode is "symmetric" or "asymmetric"
        const char *key_path = NULL;
        if (strcmp(cf->key_mode, "symmetric") == 0) 
            key_path = cf->sym_key_path;
        else key_path = cf->public_key_path;

        return send_encrypted_file_via_https(
            ctx->curl,
            cf->url,
            file_path,
            cf->cert_path,
            key_path,
            cf->key_mode,
            cf->on_all
        );
    } else {
        if (!cf->key_mode) return send_file_via_ws(ctx->cf->url, file_path);
        
        // key_mode is "symmetric" or "asymmetric"
        const char *key_path = NULL;
        if (strcmp(cf->key_mode, "symmetric") == 0) 
            key_path = cf->sym_key_path;
        else key_path = cf->public_key_path;

        return send_encrypted_file_via_ws(
            cf->url,
            file_path,
            key_path,
            cf->key_mode,
            cf->on_all
        );
    }
}

// For encrypt/decrypt with symmetric key
int sym_file_callback(const char *file_path, void *ctx_void) {
    sym_ctx_t *ctx = (sym_ctx_t*)ctx_void;
    key_mode_config_t *cf = ctx->cf;

    // For directory mode, we simply do in-place by default
    const char *dest = file_path;
    if (cf->dest_path && strcmp(cf->init_path, cf->dest_path) != 0) {
        // If dest_path is different and we want per-file dest in a directory,
        // extend here (build dest = dest_dir + basename(file_path)).
        dest = file_path;
    }

    if (strcmp(cf->mode, "encrypt") == 0) {
        return encrypt_file_symmetric(ctx->key, file_path, dest);
    } else {
        return decrypt_file_symmetric(ctx->key, file_path, dest);
    }
}

// For encrypt/decrypt with asymmetric key
int asym_file_callback(const char *file_path, void *ctx_void) {
    asym_ctx_t *ctx = (asym_ctx_t*)ctx_void;
    key_mode_config_t *cf = ctx->cf;

    const char *dest = file_path;
    if (cf->dest_path && strcmp(cf->init_path, cf->dest_path) != 0) {
        // Same note as in symmetric: extend if we want a separate dest dir.
        dest = file_path;
    }

    if (!ctx->is_decrypt) { // encrypt
        return encrypt_file_asymmetric(ctx->pub_key, file_path, dest, cf->on_all);
    } else { // decrypt
        return decrypt_file_asymmetric(ctx->pub_key, ctx->pr_key, file_path, dest, cf->on_all);
    }
}
