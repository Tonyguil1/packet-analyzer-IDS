
#pragma once

#include "PacketParser.h"

#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

struct IDSConfig {
    size_t portScanThreshold = 20;
    double portScanWindow = 10.0;

    size_t synFloodThreshold = 100;
    double synFloodWindow = 5.0;

    size_t icmpFloodThreshold = 100;
    double icmpFloodWindow = 5.0;

    double alertCooldown = 15.0;
};

struct SecurityAlert {
    std::string type;
    std::string severity;
    std::string sourceIP;
    std::string destinationIP;

    size_t count = 0;
    double timestamp = 0.0;
    double window = 0.0;
};

class DetectionEngine {
public:
    explicit DetectionEngine(
        const IDSConfig& config = IDSConfig{}
    );

    // Returns false if the config cannot be loaded.
    bool loadConfig(const std::string& filename);

    std::vector<SecurityAlert> analyze(
        const ParsedPacket& packet,
        double timestamp
    );

    static void printAlert(const SecurityAlert& alert);

private:
    using FlowKey =
        std::pair<std::string, std::string>;

    struct PortHistory {
        std::deque<std::pair<double, uint16_t>> events;
        double lastAlert =
            -std::numeric_limits<double>::infinity();
    };

    struct RateHistory {
        std::deque<double> events;
        double lastAlert =
            -std::numeric_limits<double>::infinity();
    };

    IDSConfig config;

    std::map<FlowKey, PortHistory> portHistory;
    std::map<FlowKey, RateHistory> synHistory;
    std::map<FlowKey, RateHistory> icmpHistory;

    void detectPortScan(
        const ParsedPacket& packet,
        double timestamp,
        std::vector<SecurityAlert>& alerts
    );

    void detectSynFlood(
        const ParsedPacket& packet,
        double timestamp,
        std::vector<SecurityAlert>& alerts
    );

    void detectIcmpFlood(
        const ParsedPacket& packet,
        double timestamp,
        std::vector<SecurityAlert>& alerts
    );

    static void prune(
        std::deque<double>& events,
        double now,
        double window
    );

    static bool canAlert(
        double now,
        double lastAlert,
        double cooldown
    );
};
