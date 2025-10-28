#include "minidrive/protocol.hpp"

#include <cstring>      // std::memcpy
#include <stdexcept>    // std::length_error
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

// Lokálne helpery na big-endian zápis/čítanie 32-bit čísla.
namespace {
inline void write_u32_be(uint32_t v, unsigned char out[4]) {
    out[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
    out[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
    out[2] = static_cast<unsigned char>((v >> 8)  & 0xFF);
    out[3] = static_cast<unsigned char>( v        & 0xFF);
}

inline uint32_t read_u32_be(const unsigned char in[4]) {
    return (uint32_t(in[0]) << 24) |
           (uint32_t(in[1]) << 16) |
           (uint32_t(in[2]) << 8)  |
            uint32_t(in[3]);
}
} // namespace

namespace minidrive {

std::vector<uint8_t> frame_json(const nlohmann::json& j) {
    const std::string payload = j.dump();

    if (payload.size() > 0xFFFFFFFFu) {
        throw std::length_error("JSON payload too large (>4 GiB)");
    }

    unsigned char hdr[4];
    write_u32_be(static_cast<uint32_t>(payload.size()), hdr);

    std::vector<uint8_t> out;
    out.resize(4 + payload.size());
    std::memcpy(out.data(), hdr, 4);
    std::memcpy(out.data() + 4, payload.data(), payload.size());
    return out;
}

bool try_extract_framed_json(std::string& inbuf, nlohmann::json& out) {
    if (inbuf.size() < 4) return false;

    unsigned char hdr[4];
    std::memcpy(hdr, inbuf.data(), 4);
    const uint32_t len = read_u32_be(hdr);

    if (inbuf.size() < static_cast<size_t>(4 + len)) return false;

    const std::string payload = inbuf.substr(4, len);
    out = nlohmann::json::parse(payload);   // ak je payload neplatný JSON, vyhodí výnimku
    inbuf.erase(0, 4 + len);
    return true;
}

} // namespace minidrive