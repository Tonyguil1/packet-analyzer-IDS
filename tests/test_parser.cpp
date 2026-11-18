#include "PacketParser.h"

#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
    PacketParser parser;
    ParsedPacket result;

    // Ethernet requires at least 14 bytes.
    uint8_t shortPacket[5] = {0};

    ParseResult status = parser.parse(
        shortPacket,
        sizeof(shortPacket),
        sizeof(shortPacket),
        result
    );

    assert(status == ParseResult::Malformed);

    std::cout << "Malformed packet test passed!\n";

    return 0;
}
