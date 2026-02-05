#pragma once

#include <cstdint>
#include <ostream>
#include <istream>

#include "defaults.h"

static void u32_to_le(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

static void u64_to_le(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8*i));
}

static uint32_t u32_from_le(const uint8_t in[4]) {
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static uint64_t u64_from_le(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)in[i] << (8*i));
    return v;
}

static void write_u32_le(std::ostream& out, uint32_t v) {
    uint8_t b[4] = { 
        (uint8_t)v, 
        (uint8_t)(v>>8), 
        (uint8_t)(v>>16), 
        (uint8_t)(v>>24) 
    };
    out.write((char*)b, 4);
}

static void write_u64_le(std::ostream& out, uint64_t v) {
    uint8_t b[8];
    for (int i=0;i<8;i++) b[i] = (uint8_t)(v >> (8*i));
    out.write((char*)b, 8);
}

static bool read_u32_le(std::istream& in, uint32_t& v) {
    uint8_t b[4]; if (!in.read((char*)b, 4)) return false;
    v = (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
    return true;
}

static bool read_u64_le(std::istream& in, uint64_t& v) {
    uint8_t b[8]; if (!in.read((char*)b, 8)) return false;
    v = 0; for (int i=0;i<8;i++) v |= ((uint64_t)b[i] << (8*i));
    return true;
}

inline bool is_hidden_or_tmp(const std::string& name) {
    if (name.empty() || name[0] == '.') return true;

    constexpr const char* TEMP_EXTS[] = {
        ".tmp",
        ".temp",
        "~",
        ".part",
        ".swp",
    };

    auto s = strlen(name.c_str());
    for (auto ext : TEMP_EXTS) {
        auto e = strlen(ext);
        if (s >= e && name.compare(s-e, e, ext) == 0) return true;
    }

    return false;
}

static inline std::string_view sv_dirname(std::string_view p) {
    if (p.empty()) return ".";
    size_t pos = p.find_last_of('/');
    if (pos == std::string_view::npos) return ".";
    if (pos == 0) return "/";
    return p.substr(0, pos);
}

static inline std::string_view sv_basename(std::string_view p) {
    size_t pos = p.find_last_of('/');
    return (pos == std::string_view::npos) ? p : p.substr(pos + 1);
}

static inline bool has_glob(std::string_view p) {
    return p.find_first_of("*?") != std::string_view::npos;
}

static inline void join2(std::string& out, std::string_view a, std::string_view b) {
    // out = a + "/" + b  (handles a="." or "/")
    out.clear();
    out.reserve(a.size() + 1 + b.size());
    out.append(a.data(), a.size());
    if (!out.empty() && out.back() != '/') out.push_back('/');
    out.append(b.data(), b.size());
}

static inline void append_suffix(std::string& out, std::string_view base, std::string_view suf) {
    out.assign(base.data(), base.size());
    out.append(suf.data(), suf.size());
}

static inline std::string_view strip_suffix(std::string_view s, std::string_view suf) {
    auto s_size = s.size();
    auto suf_size = suf.size();
    return s_size >= suf_size && s.substr(s_size - suf_size) == suf 
        ? s.substr(0, s_size - suf_size) 
        : s;
}

static inline std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace((unsigned char)s.front())) s.remove_prefix(1);
    while (!s.empty() && std::isspace((unsigned char)s.back()))  s.remove_suffix(1);
    return s;
}

static inline bool ieq(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) {
            return false;
        }
    }
    return true;
}

inline const char* getenv_or_default(const char* env_name, const char* default_val) {
    const char* env = std::getenv(env_name);
    if (env) {
        return env;
    } else {
        fprintf(
            stderr,
            YELLOW "[WARN] No %s found in environment. Using default: %s\n" RESET, env_name, default_val
        );
        return default_val;
    }
}