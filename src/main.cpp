#include "PacketCapture.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc == 2) {
        PacketCapture capture(argv[1]);
        return capture.startCapture() ? 0 : 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Error: " << errbuf << '\n';
        return 1;
    }

    std::cout << "Available interfaces:\n\n";

    for (pcap_if_t* device = devices;
         device != nullptr;
         device = device->next) {

        std::cout << "Interface: "
                  << device->name << '\n';

        if (device->description != nullptr) {
            std::cout << "Description: "
                      << device->description << '\n';
        }

        std::cout << '\n';
    }

    pcap_freealldevs(devices);

    std::cout << "Usage: sudo ./packet-ids "
              << "<interface>\n";

    return 0;
}
