#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace minidrive {
    std::vector<uint8_t> frame_json(const nlohmann::json& j);     
    bool try_extract_framed_json(std::string& inbuf, nlohmann::json& out);
} 