#include <iostream>
#include <yaml-cpp/yaml.h>
#include <cstdint>
#include <string>
#include <regex>

struct process_rule {
    uint32_t target_pid;
    uint64_t rate_bps;
    uint8_t  gress;
    uint32_t time_scale;
};

// 将 "1M" 转换为整数 bps
uint64_t parse_rate_bps(const std::string& rate_str) {
    std::regex pattern(R"((\d+)([KMG]?))");
    std::smatch match;
    if (std::regex_match(rate_str, match, pattern)) {
        uint64_t base = std::stoull(match[1].str());
        std::string unit = match[2].str();
        if (unit == "K") return base * 1000;
        if (unit == "M") return base * 1000 * 1000;
        if (unit == "G") return base * 1000 * 1000 * 1000;
        return base;
    }
    throw std::runtime_error("Invalid rate_bps format");
}

// 将 "1s" 转换为秒数
uint32_t parse_time_scale(const std::string& time_str) {
    std::regex pattern(R"((\d+)(s|ms|m))");
    std::smatch match;
    if (std::regex_match(time_str, match, pattern)) {
        uint32_t base = std::stoul(match[1].str());
        std::string unit = match[2].str();
        if (unit == "ms") return base / 1000;
        if (unit == "m")  return base * 60;
        return base; // "s"
    }
    throw std::runtime_error("Invalid time_scale format");
}

// 将 "engress"/"ingress" 映射为枚举值
uint8_t parse_gress(const std::string& gress_str) {
    if (gress_str == "ingress") return 0;
    if (gress_str == "engress") return 1;
    throw std::runtime_error("Invalid gress value");
}

int main() {
    YAML::Node config = YAML::LoadFile("../config.yaml");
    const auto& node = config["process_rule"];

    process_rule rule;
    rule.target_pid = node["target_pid"].as<uint32_t>();
    rule.rate_bps   = parse_rate_bps(node["rate_bps"].as<std::string>());
    rule.gress      = parse_gress(node["gress"].as<std::string>());
    rule.time_scale = parse_time_scale(node["time_scale"].as<std::string>());

    std::cout << "PID: " << rule.target_pid << "\n";
    std::cout << "Rate: " << rule.rate_bps << " bps\n";
    std::cout << "Gress: " << static_cast<int>(rule.gress) << "\n";
    std::cout << "Time Scale: " << rule.time_scale << " sec\n";

    return 0;
}
