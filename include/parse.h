#pragma once

#include <string>
#include <regex>
#include <stdexcept>
#include <cstdint>

inline uint64_t parse_rate_bps(const std::string& rate_str) {
    std::regex pattern(R"((\d+)([KMG]?))");
    std::smatch match;
    if (std::regex_match(rate_str, match, pattern)) {
        uint64_t base = std::stoull(match[1].str());
        std::string unit = match[2].str();
        if (unit == "K") return base * 1024ULL;
        if (unit == "M") return base * 1024ULL * 1024;
        if (unit == "G") return base * 1024ULL * 1024 * 1024;
        return base;
    }
    throw std::runtime_error("Invalid rate_bps format: " + rate_str);
}

inline uint32_t parse_time_scale(const std::string& time_str) {
    std::regex pattern(R"((\d+)(s|ms|m))");
    std::smatch match;
    if (std::regex_match(time_str, match, pattern)) {
        uint32_t base = std::stoul(match[1].str());
        std::string unit = match[2].str();
        if (unit == "ms") return base / 1000;
        if (unit == "m")  return base * 60;
        return base; // "s"
    }
    throw std::runtime_error("Invalid time_scale format: " + time_str);
}


inline uint8_t parse_gress(const std::string& gress_str) {
    if (gress_str == "ingress") return 0;
    if (gress_str == "egress")  return 1;
    throw std::runtime_error("Invalid gress value: " + gress_str);
}
