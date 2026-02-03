#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "defaults.h"
#include "helpers.h"

static inline bool sv_ends_with(std::string_view s, std::string_view suf) {
    return s.size() >= suf.size() && s.substr(s.size() - suf.size()) == suf;
}

enum class DestPathMode : uint8_t { 
    IN_PLACE, 
    DEST_DIR, 
    DEST_FILE 
};

struct DestPath {
    DestPathMode mode = DestPathMode::IN_PLACE;
    std::string dest;  // for DEST_DIR or DEST_FILE; empty for IN_PLACE
    bool ok = true;
};

class DirectoryProcessor {
private:
    static int match_pattern(std::string_view p, const char* t) {
        size_t p_idx = 0, t_idx = 0;
        size_t star_pos = (size_t)-1, match_pos = 0;

        const size_t p_len = p.size();
        const size_t t_len = std::strlen(t);

        while (t_idx < t_len) {
            if (p_idx < p_len && p[p_idx] == '*') {
                star_pos = p_idx++;
                match_pos = t_idx;
            } else if (p_idx < p_len && (p[p_idx] == '?' || p[p_idx] == t[t_idx])) {
                ++p_idx; ++t_idx;
            } else if (star_pos != (size_t)-1) {
                p_idx = star_pos + 1;
                t_idx = ++match_pos;
            } else {
                return 0;
            }
        }
        while (p_idx < p_len && p[p_idx] == '*') ++p_idx;
        return (p_idx == p_len) ? 1 : 0;
    }

    static DestPath init_dest_path(std::string_view init, std::string_view dest) {
        DestPath dp{};
        if (dest.empty()) {
            dp.mode = DestPathMode::IN_PLACE;
            return dp;
        }

        // If init is glob -> dest is treated as directory root
        auto pos = init.find_first_of("*?");
        if (pos != std::string_view::npos) {
            dp.mode = DestPathMode::DEST_DIR;
            dp.dest = init.substr(0, pos);
            return dp;
        }

        std::string init_s(init);
        std::string dest_s(dest);

        struct stat st{};
        if (::stat(init_s.c_str(), &st) != 0) {
            // if init doesn't exist, guess based on dest type
            struct stat dst{};
            bool dest_is_dir = (::stat(dest_s.c_str(), &dst) == 0 && S_ISDIR(dst.st_mode));
            dp.mode = dest_is_dir ? DestPathMode::DEST_DIR : DestPathMode::DEST_FILE;
            dp.dest = std::move(dest_s);
            return dp;
        }

        if (S_ISDIR(st.st_mode)) {
            dp.mode = DestPathMode::DEST_DIR;
            dp.dest = std::move(dest_s);
            return dp;
        }

        if (S_ISREG(st.st_mode)) {
            struct stat dst{};
            bool dest_is_dir = (::stat(dest_s.c_str(), &dst) == 0 && S_ISDIR(dst.st_mode));
            dp.mode = dest_is_dir ? DestPathMode::DEST_DIR : DestPathMode::DEST_FILE;
            dp.dest = std::move(dest_s);
            return dp;
        }

        dp.ok = false;
        return dp;
    }

    static void map_dest_path(std::string& dst_out, const DestPath& plan, std::string_view src_dir, std::string_view name, std::string_view name_override = {}) {
        std::string_view final_name = name_override.empty() ? name : name_override;

        switch (plan.mode) {
            case DestPathMode::IN_PLACE:
                join2(dst_out, src_dir, final_name);
                break;
            case DestPathMode::DEST_DIR:
                join2(dst_out, plan.dest, final_name);
                break;
            case DestPathMode::DEST_FILE:
                dst_out.assign(plan.dest);
                break;
        }
    }

    template<class OnFile>
    static int process_dir_openat(std::string_view dir_sv, std::string_view pattern, OnFile&& on_file) {
        std::string dir(dir_sv);
        DIR* d = ::opendir(dir.c_str());
        if (!d) {
            perror("[ERROR] opendir");
            return -1;
        }
        const int dfd = ::dirfd(d);

        int rc = 0;
        for (;;) {
            errno = 0;
            dirent* ent = ::readdir(d);
            if (!ent) {
                if (errno) { std::perror("[ERROR] readdir"); rc = -1; }
                break;
            }

            const char* name = ent->d_name;
            if (is_hidden_or_tmp(name)) continue;

            if (!pattern.empty() && !match_pattern(pattern, name)) continue;

            bool is_reg = false;
            if (ent->d_type == DT_REG) {
                is_reg = true;
            } else if (ent->d_type == DT_UNKNOWN) {
                struct stat st{};
                if (::fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) { rc = -1; continue; }
                if (!S_ISREG(st.st_mode)) continue;
                is_reg = true;
            } else {
                continue;
            }
            if (!is_reg) continue;

            int fd = ::openat(dfd, name, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                fprintf(stderr, "[WARN] openat failed (%s/%s): %s\n", dir.c_str(), name, std::strerror(errno));
                rc = -1;
                continue;
            }

            bool cont = on_file(dir_sv, name, dfd, fd);
            ::close(fd);

            if (!cont) break;
        }

        ::closedir(d);
        return rc;
    }

    template<class OnFile>
    static int process_path_openat(std::string_view init, OnFile&& on_file) {
        if (has_glob(init)) {
            const auto slash = init.find_last_of('/');
            std::string_view dir = (slash == std::string_view::npos) ? "." : init.substr(0, slash);
            std::string_view pat = (slash == std::string_view::npos) ? init : init.substr(slash + 1);

            std::string dir_s(dir);
            struct stat st{};
            if (::stat(dir_s.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                fprintf(stderr, "[ERROR] glob base is not a directory: %s\n", dir_s.c_str());
                return -1;
            }
            return process_dir_openat(dir, pat, std::forward<OnFile>(on_file));
        }

        std::string init_s(init);
        struct stat st{};
        if (::stat(init_s.c_str(), &st) != 0) {
            perror("[ERROR] stat");
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            return process_dir_openat(init, "", std::forward<OnFile>(on_file));
        }

        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "[ERROR] %s is neither file nor directory\n", init_s.c_str());
            return -1;
        }

        // Single file: open parent directory + openat child => enables unlinkat.
        std::string_view dir_sv = sv_dirname(init_s);
        std::string_view name_sv = sv_basename(init_s);

        std::string dir_s(dir_sv);
        int dfd = ::open(dir_s.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) {
            fprintf(
                stderr, 
                "[ERROR] open dir failed (%s): %s\n", dir_s.c_str(), strerror(errno)
            );
            return -1;
        }

        int fd = ::openat(dfd, name_sv.data(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(
                stderr, 
                "[ERROR] openat failed (%s/%.*s): %s\n",
                dir_s.c_str(), (int)name_sv.size(), name_sv.data(), strerror(errno)
            );
            ::close(dfd);
            return -1;
        }

        (void)on_file(dir_sv, name_sv.data(), dfd, fd);
        ::close(fd);
        ::close(dfd);
        return 0;
    }

    static inline void append_suffix(std::string& out, const char* name, std::string_view suffix) {
        out.assign(name);
        out.append(suffix.data(), suffix.size());
    }

    static inline void strip_suffix(std::string_view src_name, std::string& out_name, std::string_view suffix) {
        if (sv_ends_with(src_name, suffix)) {
            out_name.assign(src_name.data(), src_name.size() - 4);
        } else {
            out_name.assign(src_name.data(), src_name.size());
        }
    }

public:
    // Encrypt: enc_fn(in_fd, dst_path) -> int
    //  Default: skip *.enc inputs
    template<class EncryptFn>
    int process_encrypt(std::string_view init, std::string_view dest, bool archive, bool force, EncryptFn&& enc_fn) {
        DestPath plan = init_dest_path(init, dest);
        if (!plan.ok) return -1;

        std::string dst;
        std::string out_name;
        int rc_local = 0;
        bool same_path;

        int rc_walk = process_path_openat(init, [&](std::string_view src_dir, const char* src_name_c, int dfd, int in_fd) -> bool {
            std::string_view src_name(src_name_c);

            if (!force && sv_ends_with(src_name, ENC)) return true;

            if (plan.mode == DestPathMode::DEST_FILE) {
                dst.assign(plan.dest);
                std::string src_full;
                join2(src_full, src_dir, src_name);
                same_path = (src_full == dst);
            } else {
                // IN_PLACE / DEST_DIR: always *.enc
                append_suffix(out_name, src_name_c, ENC);
                map_dest_path(dst, plan, src_dir, src_name, out_name);
                same_path = false;
            }

            if (enc_fn(in_fd, dst.c_str()) != 0) {
                fprintf(
                    stderr, 
                    "[ERROR] Encrypt failed: %.*s/%s -> %s\n",
                    (int)src_dir.size(), src_dir.data(), src_name_c, dst.c_str()
                );
                rc_local = -1;
                return true;
            }

            if (!archive && !same_path) {
                // Remove original only after success
                if (::unlinkat(dfd, src_name_c, 0) != 0) {
                    fprintf(
                        stderr, 
                        "[ERROR] unlinkat failed (%.*s/%s): %s\n",
                        (int)src_dir.size(), src_dir.data(), src_name_c, strerror(errno)
                    );
                    // not fatal for encryption result
                }
            }

            return true;
        });

        return (rc_walk == 0 && rc_local == 0) ? 0 : -1;
    }

    // Decrypt: dec_fn(in_fd, dst_path) -> int
    // Default: process ONLY *.enc
    template<class DecryptFn>
    int process_decrypt(std::string_view init, std::string_view dest, bool archive, bool force, DecryptFn&& dec_fn) {
        DestPath plan = init_dest_path(init, dest);
        if (!plan.ok) return -1;

        std::string dst;
        std::string out_name;
        int rc_local = 0;
        bool same_path;

        int rc_walk = process_path_openat(init, [&](std::string_view src_dir, const char* src_name_c, int dfd, int in_fd) -> bool {
            std::string_view src_name(src_name_c);
            const bool has_enc = sv_ends_with(src_name, ENC);

            if (!force && !has_enc) return true;

            if (plan.mode == DestPathMode::DEST_FILE) {
                dst.assign(plan.dest);
                std::string src_full;
                join2(src_full, src_dir, src_name);
                same_path = (src_full == dst);
            } else {
                if (has_enc) {
                    // strip .enc
                    out_name.assign(src_name.data(), src_name.size() - 4);
                } else {
                    append_suffix(out_name, src_name_c, ".dec");
                }
                map_dest_path(dst, plan, src_dir, src_name, out_name);
                same_path = false;
            }

            int drc = dec_fn(in_fd, dst.c_str());
            if (drc != 0) {
                if (force && !has_enc) {
                    // Treat as NOT_ENCRYPTED / SKIP in force mode (not an error)
                    fprintf(
                        stdout, 
                        "[SKIP] Not encrypted (force): %.*s/%s\n",
                        (int)src_dir.size(), src_dir.data(), src_name_c
                    );
                    return true;
                }

                fprintf(
                    stderr, 
                    "[WARN] Decrypt failed: %.*s/%s -> %s\n",
                    (int)src_dir.size(), src_dir.data(), src_name_c, dst.c_str()
                );
                rc_local = -1;
                return true;
            }

            if (!archive && !same_path) {
                if (::unlinkat(dfd, src_name_c, 0) != 0) {
                    fprintf(
                        stderr, 
                        "[WARN] unlinkat failed (%.*s/%s): %s\n",
                        (int)src_dir.size(), src_dir.data(), src_name_c, strerror(errno)
                    );
                }
            }

            return true;
        });

        return (rc_walk == 0 && rc_local == 0) ? 0 : -1;
    }
};