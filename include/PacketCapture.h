#pragma once

#include <pcap/pcap.h>
#include <string>

class PacketCapture {
public:
    explicit PacketCapture(const std::string& interfaceName);

    bool startCapture();

private:
    std::string interfaceName;

    static void packetHandler(
        u_char* userData,
        const pcap_pkthdr* header,
        const u_char* packet
    );
};
