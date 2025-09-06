#pragma once

#include <string>
#include <regex>
#include <stdexcept>
#include <cstdint>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>    // inet_pton, inet_ntop, htonl, ntohl
#include <netinet/in.h>   // IPPROTO_TCP, IPPROTO_UDP
#include <sys/socket.h>   // AF_INET

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

inline std::string ip_to_string(uint32_t ip_hbo) {
    in_addr addr;
    addr.s_addr = htonl(ip_hbo);
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

inline uint32_t parse_ip(const std::string& ip_str) {
    in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IPv4 address: " + ip_str);
    }
    // inet_pton 返回网络字节序，转换为主机字节序
    return ntohl(addr.s_addr);
}

inline std::string protocol_to_string(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default:          return std::to_string(proto);
    }
}

inline uint8_t parse_protocol(const std::string& proto_str) {
    if (proto_str == "TCP" || proto_str == "tcp") return IPPROTO_TCP;
    if (proto_str == "UDP" || proto_str == "udp") return IPPROTO_UDP;
    try {
        int v = std::stoi(proto_str);
        if (v >= 0 && v <= 255) return static_cast<uint8_t>(v);
    } catch (...) { }
    throw std::runtime_error("Invalid protocol: " + proto_str);
}


inline bool parse_flag(const YAML::Node& node) {
    if (!node || node.IsNull()) {
        throw std::runtime_error("Missing flag node");
    }

    // 如果本身就是布尔类型，直接返回
    if (node.IsScalar() && (node.Tag() == "!bool" || node.Tag().empty())) {
        try {
            return node.as<bool>();
        } catch (...) {
            // 继续尝试当字符串处理
        }
    }

    // 当作字符串处理
    std::string s = node.as<std::string>();
    // 转小写
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    if (s == "enable"   || s == "enabled"  || s == "true")  return true;
    if (s == "disable"  || s == "disabled" || s == "false") return false;

    throw std::runtime_error("Invalid flag value: " + s);
}

inline std::string format_elapsed_ns(uint64_t ns_since_boot) {
    // 转成毫秒
    uint64_t total_ms = ns_since_boot / 1'000'000ULL;
    uint64_t hours    = total_ms / 3'600'000ULL;
    uint64_t minutes  = (total_ms % 3'600'000ULL) / 60'000ULL;
    uint64_t seconds  = (total_ms % 60'000ULL)     / 1'000ULL;
    uint64_t millis   = total_ms % 1'000ULL;

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << hours   << ':'
        << std::setw(2) << minutes << ':'
        << std::setw(2) << seconds << '.'
        << std::setw(3) << millis;
    return oss.str();
}