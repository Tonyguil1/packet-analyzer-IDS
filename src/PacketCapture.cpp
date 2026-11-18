#include "PacketCapture.h"
#include "PacketParser.h"

#include <iostream>

PacketCapture::PacketCapture(
    const std::string& interfaceName
) : interfaceName(interfaceName) {}

bool PacketCapture::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        interfaceName.c_str(),
        65535,
        0,
        1000,
        errbuf
    );

    if (handle == nullptr) {
        std::cerr << "Capture error: "
                  << errbuf << '\n';
        return false;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Unsupported link type. "
                  << "Ethernet required.\n";

        pcap_close(handle);
        return false;
    }

    std::cout << "Capturing on: "
              << interfaceName << '\n';

    std::cout << "Press Ctrl+C to stop.\n";

    int status = pcap_loop(
        handle,
        -1,
        packetHandler,
        nullptr
    );

    if (status == PCAP_ERROR) {
        std::cerr << "Capture failed: "
                  << pcap_geterr(handle) << '\n';
    }

    pcap_close(handle);

    return status >= 0;
}

void PacketCapture::packetHandler(
    u_char* userData,
    const pcap_pkthdr* header,
    const u_char* packet
) {
    (void)userData;

    PacketParser parser;
    ParsedPacket parsed;

    ParseResult status = parser.parse(
        packet,
        header->caplen,
        header->len,
        parsed
    );

    if (status == ParseResult::Success) {
        PacketParser::printPacket(parsed);
    }
    else if (status == ParseResult::Malformed) {
        std::cerr << "[WARNING] Malformed or "
                  << "truncated packet\n";
    }

    // Unsupported protocols are ignored for now.
}
