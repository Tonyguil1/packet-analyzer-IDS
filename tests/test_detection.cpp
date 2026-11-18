
#include "DetectionEngine.h"

#include <cassert>
#include <iostream>

ParsedPacket createTCPPacket(
    uint16_t port,
    uint8_t flags = 0x02
) {
    ParsedPacket packet;

    packet.sourceIP = "192.168.1.50";
    packet.destinationIP = "192.168.1.100";

    packet.protocol = "TCP";
    packet.sourcePort = 50000;
    packet.destinationPort = port;

    packet.tcpFlags = flags;
    packet.hasPorts = true;
    packet.hasTCPFlags = true;

    return packet;
}

ParsedPacket createICMPPacket() {
    ParsedPacket packet;

    packet.sourceIP = "192.168.1.50";
    packet.destinationIP = "192.168.1.100";

    packet.protocol = "ICMP";
    packet.icmpType = 8;
    packet.icmpCode = 0;
    packet.hasICMP = true;

    return packet;
}

int main() {
    // Test 1: Port scan detection.
    {
        IDSConfig config;
        config.portScanThreshold = 3;
        config.synFloodThreshold = 100;
        config.alertCooldown = 15;

        DetectionEngine ids(config);

        assert(ids.analyze(
            createTCPPacket(21), 1.0
        ).empty());

        assert(ids.analyze(
            createTCPPacket(22), 2.0
        ).empty());

        auto alerts = ids.analyze(
            createTCPPacket(23), 3.0
        );

        assert(alerts.size() == 1);
        assert(alerts[0].type == "Possible Port Scan");

        std::cout << "[PASS] Port scan detection\n";

        // Repeated traffic should not immediately
        // produce another alert.
        assert(ids.analyze(
            createTCPPacket(25), 4.0
        ).empty());

        std::cout << "[PASS] Alert cooldown\n";
    }

    // Test 2: SYN flood detection.
    {
        IDSConfig config;
        config.portScanThreshold = 100;
        config.synFloodThreshold = 3;

        DetectionEngine ids(config);

        assert(ids.analyze(
            createTCPPacket(443), 1.0
        ).empty());

        assert(ids.analyze(
            createTCPPacket(443), 2.0
        ).empty());

        auto alerts = ids.analyze(
            createTCPPacket(443), 3.0
        );

        assert(alerts.size() == 1);
        assert(alerts[0].type == "Possible SYN Flood");

        std::cout << "[PASS] SYN flood detection\n";
    }

    // Test 3: ICMP flood detection.
    {
        IDSConfig config;
        config.icmpFloodThreshold = 3;

        DetectionEngine ids(config);

        assert(ids.analyze(
            createICMPPacket(), 1.0
        ).empty());

        assert(ids.analyze(
            createICMPPacket(), 2.0
        ).empty());

        auto alerts = ids.analyze(
            createICMPPacket(), 3.0
        );

        assert(alerts.size() == 1);
        assert(alerts[0].type == "Possible ICMP Flood");

        std::cout << "[PASS] ICMP flood detection\n";
    }

    // Test 4: Expired events do not trigger an alert.
    {
        IDSConfig config;
        config.synFloodThreshold = 3;
        config.synFloodWindow = 5;
        config.portScanThreshold = 100;

        DetectionEngine ids(config);

        ids.analyze(createTCPPacket(80), 1.0);
        ids.analyze(createTCPPacket(80), 2.0);

        auto alerts = ids.analyze(
            createTCPPacket(80), 20.0
        );

        assert(alerts.empty());

        std::cout << "[PASS] Sliding window expiration\n";
    }

    std::cout << "\nAll IDS tests passed!\n";

    return 0;
}
