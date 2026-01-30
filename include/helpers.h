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

static std::string dirname_of(std::string_view path) {
    if (path.empty()) return ".";
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";

    if (pos == 0) return "/";

    return std::string(path.substr(0, pos));
}

static void join(std::string& out, std::string_view dir, std::string_view name) {
    out.clear();
    out.reserve(dir.size() + 1 + name.size());
    out.append(dir);
    if (!out.empty() && out.back() != '/') out.push_back('/');
    out.append(name);
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