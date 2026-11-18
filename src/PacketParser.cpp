
#include "PacketParser.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace {

uint16_t read16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8)
         | static_cast<uint16_t>(data[1]);
}

} // namespace

std::string PacketParser::formatMAC(const uint8_t* mac) {
    std::ostringstream ss;

    ss << std::hex << std::setfill('0');

    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";

        ss << std::setw(2)
           << static_cast<unsigned>(mac[i]);
    }

    return ss.str();
}

std::string PacketParser::formatIP(const uint8_t* ip) {
    std::ostringstream ss;

    for (int i = 0; i < 4; ++i) {
        if (i > 0) ss << ".";

        ss << static_cast<unsigned>(ip[i]);
    }

    return ss.str();
}

std::string PacketParser::formatTCPFlags(uint8_t flags) {
    std::string result;

    if (flags & 0x01) result += "FIN ";
    if (flags & 0x02) result += "SYN ";
    if (flags & 0x04) result += "RST ";
    if (flags & 0x08) result += "PSH ";
    if (flags & 0x10) result += "ACK ";
    if (flags & 0x20) result += "URG ";
    if (flags & 0x40) result += "ECE ";
    if (flags & 0x80) result += "CWR ";

    if (result.empty()) return "NONE";

    result.pop_back();
    return result;
}

ParseResult PacketParser::parse(
    const uint8_t* data,
    size_t capturedLength,
    uint32_t originalLength,
    ParsedPacket& result
) const {
    // Clear data from previous packets.
    result = ParsedPacket{};
    result.packetSize = originalLength;

    if (data == nullptr || capturedLength < 14) {
        return ParseResult::Malformed;
    }

    // ------------------------
    // Ethernet header
    // ------------------------

    result.destinationMAC = formatMAC(data);
    result.sourceMAC = formatMAC(data + 6);

    uint16_t etherType = read16(data + 12);

    size_t offset = 14;

    // Handle a single 802.1Q / 802.1ad VLAN tag.
    if (etherType == 0x8100 || etherType == 0x88A8) {
        if (capturedLength < offset + 4) {
            return ParseResult::Malformed;
        }

        etherType = read16(data + offset + 2);
        offset += 4;
    }

    // This version supports IPv4 only.
    if (etherType != 0x0800) {
        return ParseResult::Unsupported;
    }

    // ------------------------
    // IPv4 header
    // ------------------------

    if (capturedLength < offset + 20) {
        return ParseResult::Malformed;
    }

    uint8_t version = data[offset] >> 4;
    size_t ipHeaderLength =
        static_cast<size_t>(data[offset] & 0x0F) * 4;

    if (version != 4 || ipHeaderLength < 20) {
        return ParseResult::Malformed;
    }

    if (capturedLength < offset + ipHeaderLength) {
        return ParseResult::Malformed;
    }

    uint16_t ipTotalLength = read16(data + offset + 2);

    if (ipTotalLength < ipHeaderLength) {
        return ParseResult::Malformed;
    }

    result.ttl = data[offset + 8];
    result.sourceIP = formatIP(data + offset + 12);
    result.destinationIP = formatIP(data + offset + 16);

    uint8_t protocol = data[offset + 9];

    uint16_t fragmentField = read16(data + offset + 6);

    bool moreFragments = (fragmentField & 0x2000) != 0;
    bool nonzeroOffset = (fragmentField & 0x1FFF) != 0;

    result.fragmented = moreFragments || nonzeroOffset;

    // Stay within the captured data and IPv4 total length.
    size_t availableIPBytes = std::min(
        capturedLength - offset,
        static_cast<size_t>(ipTotalLength)
    );

    size_t transportOffset = offset + ipHeaderLength;
    size_t transportLength = availableIPBytes - ipHeaderLength;

    // Identify protocol even if its payload is fragmented.
    switch (protocol) {
        case 6:  result.protocol = "TCP";  break;
        case 17: result.protocol = "UDP";  break;
        case 1:  result.protocol = "ICMP"; break;
        default: result.protocol = "OTHER"; break;
    }

    // Fragment reassembly is not implemented yet.
    // Don't interpret incomplete fragments as full headers.
    if (result.fragmented) {
        return ParseResult::Success;
    }

    // ------------------------
    // TCP header
    // ------------------------

    if (protocol == 6) {
        if (transportLength < 20) {
            return ParseResult::Malformed;
        }

        const uint8_t* tcp = data + transportOffset;

        size_t tcpHeaderLength =
            static_cast<size_t>(tcp[12] >> 4) * 4;

        if (tcpHeaderLength < 20 ||
            tcpHeaderLength > transportLength) {
            return ParseResult::Malformed;
        }

        result.sourcePort = read16(tcp);
        result.destinationPort = read16(tcp + 2);

        result.tcpFlags = tcp[13];

        result.hasPorts = true;
        result.hasTCPFlags = true;
    }

    // ------------------------
    // UDP header
    // ------------------------

    else if (protocol == 17) {
        if (transportLength < 8) {
            return ParseResult::Malformed;
        }

        const uint8_t* udp = data + transportOffset;

        uint16_t udpLength = read16(udp + 4);

        if (udpLength < 8) {
            return ParseResult::Malformed;
        }

        result.sourcePort = read16(udp);
        result.destinationPort = read16(udp + 2);

        result.hasPorts = true;
    }

    // ------------------------
    // ICMP header
    // ------------------------

    else if (protocol == 1) {
        if (transportLength < 4) {
            return ParseResult::Malformed;
        }

        const uint8_t* icmp = data + transportOffset;

        result.icmpType = icmp[0];
        result.icmpCode = icmp[1];
        result.hasICMP = true;
    }

    return ParseResult::Success;
}

void PacketParser::printPacket(
    const ParsedPacket& packet
) {
    std::cout << "\n========== PACKET ==========\n";

    std::cout << "Protocol: " << packet.protocol << '\n';

    std::cout << "Source MAC: "
              << packet.sourceMAC << '\n';

    std::cout << "Destination MAC: "
              << packet.destinationMAC << '\n';

    std::cout << "Source IP: "
              << packet.sourceIP << '\n';

    std::cout << "Destination IP: "
              << packet.destinationIP << '\n';

    std::cout << "TTL: "
              << static_cast<unsigned>(packet.ttl) << '\n';

    if (packet.hasPorts) {
        std::cout << "Source Port: "
                  << packet.sourcePort << '\n';

        std::cout << "Destination Port: "
                  << packet.destinationPort << '\n';
    }

    if (packet.hasTCPFlags) {
        std::cout << "TCP Flags: "
                  << formatTCPFlags(packet.tcpFlags)
                  << '\n';
    }

    if (packet.hasICMP) {
        std::cout << "ICMP Type: "
                  << static_cast<unsigned>(packet.icmpType)
                  << '\n';

        std::cout << "ICMP Code: "
                  << static_cast<unsigned>(packet.icmpCode)
                  << '\n';
    }

    if (packet.fragmented) {
        std::cout << "IPv4 Fragment: Yes "
                  << "(transport parsing skipped)\n";
    }

    std::cout << "Packet Size: "
              << packet.packetSize << " bytes\n";

    std::cout << "============================\n";
}
