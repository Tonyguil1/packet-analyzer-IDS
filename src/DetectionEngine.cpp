
#include "DetectionEngine.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>

DetectionEngine::DetectionEngine(
    const IDSConfig& config
) : config(config) {}

bool DetectionEngine::loadConfig(
    const std::string& filename
) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "Cannot open config: "
                  << filename << '\n';
        return false;
    }

    IDSConfig updated = config;
    std::string line;

    try {
        while (std::getline(file, line)) {
            // Remove comments.
            auto comment = line.find('#');
            if (comment != std::string::npos) {
                line.erase(comment);
            }

            auto pos = line.find('=');
            if (pos == std::string::npos) {
                continue;
            }

            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            // Remove whitespace.
            auto trim = [](std::string& s) {
                auto first = s.find_first_not_of(" \t\r");
                if (first == std::string::npos) {
                    s.clear();
                    return;
                }
                auto last = s.find_last_not_of(" \t\r");
                s = s.substr(first, last - first + 1);
            };

            trim(key);
            trim(value);

            if (value.empty()) {
                throw std::invalid_argument("Empty value");
            }

            // Verify the entire value is a number.
            size_t consumed = 0;
            double number = std::stod(value, &consumed);

            if (consumed != value.size() ||
                !std::isfinite(number) ||
                number < 0) {
                throw std::invalid_argument("Invalid number");
            }

            bool isThreshold =
                key == "port_scan_threshold" ||
                key == "syn_flood_threshold" ||
                key == "icmp_flood_threshold";

            if (isThreshold) {
                if (number < 1 ||
                    std::floor(number) != number ||
                    number > 1000000) {
                    throw std::invalid_argument(
                        "Invalid threshold"
                    );
                }
            } else if (key == "alert_cooldown") {
                // Zero is allowed for the cooldown.
            } else if (number <= 0) {
                throw std::invalid_argument(
                    "Window must be positive"
                );
            }

            if (key == "port_scan_threshold")
                updated.portScanThreshold =
                    static_cast<size_t>(number);

            else if (key == "port_scan_window")
                updated.portScanWindow = number;

            else if (key == "syn_flood_threshold")
                updated.synFloodThreshold =
                    static_cast<size_t>(number);

            else if (key == "syn_flood_window")
                updated.synFloodWindow = number;

            else if (key == "icmp_flood_threshold")
                updated.icmpFloodThreshold =
                    static_cast<size_t>(number);

            else if (key == "icmp_flood_window")
                updated.icmpFloodWindow = number;

            else if (key == "alert_cooldown")
                updated.alertCooldown = number;

            else
                std::cerr << "Unknown config key: "
                          << key << '\n';
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Invalid config value: "
                  << e.what() << '\n';
        return false;
    }

    config = updated;
    return true;
}

void DetectionEngine::prune(
    std::deque<double>& events,
    double now,
    double window
) {
    while (!events.empty() &&
           now - events.front() > window) {
        events.pop_front();
    }
}

bool DetectionEngine::canAlert(
    double now,
    double lastAlert,
    double cooldown
) {
    return now - lastAlert >= cooldown;
}

void DetectionEngine::detectPortScan(
    const ParsedPacket& packet,
    double timestamp,
    std::vector<SecurityAlert>& alerts
) {
    if (!packet.hasPorts || packet.fragmented) {
        return;
    }

    bool isProbe = false;

    if (packet.protocol == "TCP" &&
        packet.hasTCPFlags) {
        bool syn = (packet.tcpFlags & 0x02) != 0;
        bool ack = (packet.tcpFlags & 0x10) != 0;

        isProbe = syn && !ack;
    }
    else if (packet.protocol == "UDP") {
        isProbe = true;
    }

    if (!isProbe) {
        return;
    }

    FlowKey key = {
        packet.sourceIP,
        packet.destinationIP
    };

    auto& history = portHistory[key];

    history.events.emplace_back(
        timestamp,
        packet.destinationPort
    );

    while (!history.events.empty() &&
           timestamp - history.events.front().first >
               config.portScanWindow) {
        history.events.pop_front();
    }

    // Count unique destination ports.
    std::set<uint16_t> uniquePorts;

    for (const auto& event : history.events) {
        uniquePorts.insert(event.second);
    }

    if (uniquePorts.size() >= config.portScanThreshold &&
        canAlert(
            timestamp,
            history.lastAlert,
            config.alertCooldown
        )) {

        SecurityAlert alert;

        alert.type = "Possible Port Scan";
        alert.severity = "MEDIUM";
        alert.sourceIP = packet.sourceIP;
        alert.destinationIP = packet.destinationIP;
        alert.count = uniquePorts.size();
        alert.timestamp = timestamp;
        alert.window = config.portScanWindow;

        alerts.push_back(alert);

        history.lastAlert = timestamp;
    }
}
