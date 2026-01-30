#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <string_view>

#include "helpers.h"

enum class DestPathMode : uint8_t { 
    IN_PLACE, 
    DEST_DIR, 
    DEST_FILE 
};

typedef struct DestPath {
    DestPathMode mode = DestPathMode::IN_PLACE;
    std::string dest;  // for DEST_DIR or DEST_FILE; empty for IN_PLACE
    bool ok = true;
} DestPath;

class DirectoryProcessor {
    private:
    DestPath init_dest_path(const std::string& src, const std::string& dest) {
        DestPath dest_path{};

        if (dest.empty()) {
            dest_path.mode = DestPathMode::IN_PLACE;
            return dest_path;
        }

        // If init is glob -> dest is treated as directory root
        auto pos = src.find_first_of("*?");
        if (pos != std::string_view::npos) {
            dest_path.mode = DestPathMode::DEST_DIR;
            dest_path.dest = src.substr(0, pos);
            return dest_path;
        }

        // Determine init type once
        struct stat st{};
        if (::stat(src.c_str(), &st) != 0) {
            // treat as file input (caller will fail later anyway)
            struct stat dst{};
            dest_path.mode = ::stat(dest.c_str(), &dst) == 0 && S_ISDIR(dst.st_mode) 
                ? DestPathMode::DEST_DIR 
                : DestPathMode::DEST_FILE;
            dest_path.dest = dest;
            return dest_path;
        }

        if (S_ISDIR(st.st_mode)) {
            dest_path.mode = DestPathMode::DEST_DIR;
            dest_path.dest = dest;
            return dest_path;
        }

        if (S_ISREG(st.st_mode)) {
            struct stat dst{}; 
            dest_path.mode = ::stat(dest.c_str(), &dst) == 0 && S_ISDIR(dst.st_mode) 
                ? DestPathMode::DEST_DIR 
                : DestPathMode::DEST_FILE;
            dest_path.dest = dest;
            return dest_path;
        }

        dest_path.ok = false;
        return dest_path;
    }

    // src + plan -> dst; name_override is optional and used by decrypt only.
    void map_dest_path(std::string_view src, std::string& dest_out, const DestPath& dest_path, std::string_view name_override = {}) {
        std::string_view name;
        if (name_override.empty()) {
            auto pos = src.find_last_of('/');
            name = (pos == std::string_view::npos) ? src : src.substr(pos + 1);
        } else {
            name = name_override;
        }

        switch (dest_path.mode) {
            case DestPathMode::IN_PLACE:
                join(dest_out, dirname_of(src), name);
                break;
            case DestPathMode::DEST_DIR:
                join(dest_out, dest_path.dest, name);
                break;
            case DestPathMode::DEST_FILE:
                dest_out = dest_path.dest;
                break;
        }
    }

    public:
    int match_pattern(const char* p, const char* t) {
        size_t p_idx     = 0;
        size_t t_idx     = 0;
        size_t match_pos = 0; // position in text when last '*' was seen
        size_t star_pos  = 0; // last position of '*' in pattern

        size_t p_len = strlen(p);
        size_t t_len = strlen(t);

        while (t_idx < t_len) {
            if (p_idx < p_len && p[p_idx] == '*') {
                star_pos = p_idx++;
                match_pos = t_idx;
            }

            else if (p_idx < p_len && (p[p_idx] == '?' || p[p_idx] == t[t_idx])) {
                ++p_idx;
                ++t_idx;
            }

            else if (star_pos != std::string::npos) {
                p_idx = star_pos + 1;
                ++match_pos;
                t_idx = match_pos;
            }

            else return 0;
        }

        while (p_idx < p_len && p[p_idx] == '*') ++p_idx;

        return p_idx == p_len;
    }

    template<class OnFile>
    int process_dir(const std::string& dir, std::string_view pattern, OnFile&& on_file) {
        DIR* d = ::opendir(dir.c_str());
        if (!d) { 
            std::perror("[ERROR] opendir"); 
            return -1; 
        }

        const int dfd = ::dirfd(d);
        std::string full;
        int rc = 0;

        for (;;) {
            errno = 0;
            dirent* ent = ::readdir(d);
            if (!ent) {
                if (errno) { 
                    std::perror("[ERROR] readdir"); 
                    rc = -1; 
                }
                break;
            }

            const char* name = ent->d_name;
            if (name[0]=='.' && (name[1]=='\0' || (name[1]=='.' && name[2]=='\0'))) continue;
            if (!pattern.empty() && !match_pattern(pattern.data(), name)) continue;

            bool is_reg = false;
            if (ent->d_type == DT_REG) {
                is_reg = true;
            } else if (ent->d_type == DT_DIR) {
                continue;
            } else if (ent->d_type == DT_UNKNOWN) {
                struct stat st{};
                if (::fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) { rc = -1; continue; }
                if (!S_ISREG(st.st_mode)) continue;
                is_reg = true;
            } else {
                continue;
            }

            if (!is_reg) continue;

            join(full, dir, name);
            if (!on_file(full)) break;
        }

        ::closedir(d);
        return rc;
    }

    template<class OnFile>
    int process_path(const std::string& init, OnFile&& on_file) {
        if (init.find_first_of("*?") != std::string_view::npos) {
            std::string_view sv(init);
            std::string dir(std::string(dirname_of(sv)));
            auto pos = sv.find_last_of('/');
            std::string_view pat = (pos == std::string_view::npos) ? sv : sv.substr(pos + 1);

            struct stat st{};
            if (::stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                fprintf(
                    stderr, 
                    "[ERROR] glob base is not a directory: %s\n", dir.c_str()
                );
                return -1;
            }

            return process_dir(dir, pat, std::forward<OnFile>(on_file));
        }

        struct stat st{};
        if (::stat(init.c_str(), &st) != 0) { 
            std::perror("[ERROR] stat");
            return -1;
        }

        if (S_ISREG(st.st_mode)) {
            on_file(init);
            return 0;
        }

        if (S_ISDIR(st.st_mode)) {
            return process_dir(
                init, 
                "",
                std::forward<OnFile>(on_file)
            );
        }

        fprintf(stderr, "[ERROR] %s is neither file nor directory\n", init.c_str());

        return -1;
    }

    template<class EncryptFn>
    int process_encrypt(const std::string& init, const std::string& dest, EncryptFn&& enc_fn) {
        DestPath dest_path = init_dest_path(init, dest);
        if (!dest_path.ok) return -1;

        std::string dst;
        int ret = 0;

        int rc = process_path(init, [&](const std::string& src) -> bool {
            map_dest_path(src, dst, dest_path);
            if (enc_fn(src, dst) != 0) {
                fprintf(
                    stderr, 
                    "[ERROR] Encrypt failed: %s\n", src.c_str()
                );
                ret = -1;
            }
            return true;
        });

        return (rc == 0 && ret == 0) ? 0 : -1;
    }

    template<class DecryptFn>
    int process_decrypt(const std::string& init, const std::string& dest, DecryptFn&& decrypt_fn) {
        DestPath dest_path = init_dest_path(init, dest);
        if (!dest_path.ok) return -1;

        std::string dst;
        int ret = 0;

        int rc = process_path(init, [&](const std::string& src) -> bool {
            auto pos = src.find_last_of('/');
            std::string base = (pos == std::string_view::npos) ? src : src.substr(pos + 1);

            auto base_size = base.size();
            auto suf_size = strlen(".enc");
            std::string out_name = base_size >= suf_size && base.substr(base_size - suf_size) == ".enc" 
                ? base.substr(0, base_size - suf_size) 
                : base;

            map_dest_path(
                src, 
                dst,
                dest_path, 
                out_name
            );

            if (decrypt_fn(src, dst) != 0) {
                fprintf(
                    stderr, 
                    "[WARN] decrypt failed: %s\n", src.c_str()
                );
                ret = -1;
            }
            return true;
        });

        return (rc == 0 && ret == 0) ? 0 : -1;
    }
};