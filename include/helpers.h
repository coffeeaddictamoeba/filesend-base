#include <cstdint>
#include <ostream>
#include <istream>

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
