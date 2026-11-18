#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct ParsedPacket {
    std::string sourceMAC;
    std::string destinationMAC;

    std::string sourceIP;
    std::string destinationIP;

    std::string protocol;

    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;

    uint8_t ttl = 0;
    uint8_t tcpFlags = 0;
    uint8_t icmpType = 0;
    uint8_t icmpCode = 0;

    uint32_t packetSize = 0;

    bool hasPorts = false;
    bool hasTCPFlags = false;
    bool hasICMP = false;
    bool fragmented = false;
};

enum class ParseResult {
    Success,
    Unsupported,
    Malformed
};

class PacketParser {
public:
    ParseResult parse(
        const uint8_t* data,
        size_t capturedLength,
        uint32_t originalLength,
        ParsedPacket& result
    ) const;

    static void printPacket(const ParsedPacket& packet);

private:
    static std::string formatMAC(const uint8_t* mac);
    static std::string formatIP(const uint8_t* ip);
    static std::string formatTCPFlags(uint8_t flags);
};
