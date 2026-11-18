# C++ Network Packet Analyzer & Intrusion Detection System

A lightweight network packet analyzer and intrusion detection system (IDS) built using C++ and libpcap. The application captures live network traffic, parses network protocols, and detects suspicious activity using rule-based detection.

## Features

- **Live Packet Capture:** Captures network traffic using libpcap.
- **Packet Parsing:** Extracts Ethernet, IPv4, TCP, UDP, and ICMP header information.
- **Port Scan Detection:** Detects attempts to connect to multiple destination ports within a short period.
- **SYN Flood Detection:** Identifies unusually high volumes of TCP SYN packets.
- **ICMP Flood Detection:** Monitors excessive ICMP echo requests.
- **Configurable Rules:** Allows detection thresholds and time windows to be customized.
- **Security Alerts:** Displays alerts with severity, source/destination IPs, and detection information.

## Technologies Used

- C++17
- libpcap
- CMake
- Linux
- Standard Template Library (STL)

## Project Structure

```text
packet-ids/
├── config/
│   └── ids_rules.conf
├── include/
│   ├── PacketCapture.h
│   ├── PacketParser.h
│   └── DetectionEngine.h
├── src/
│   ├── main.cpp
│   ├── PacketCapture.cpp
│   ├── PacketParser.cpp
│   └── DetectionEngine.cpp
├── tests/
│   ├── test_parser.cpp
│   └── test_detection.cpp
├── docs/
├── CMakeLists.txt
└── README.md
```

## Installation

### 1. Install Dependencies

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev
```

### 2. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

### 3. Build the Project

```bash
cmake -S . -B build
cmake --build build
```

## Usage

### List Network Interfaces

```bash
./build/packet-ids
```

### Start Network Monitoring

```bash
sudo ./build/packet-ids enp3s0
```

Replace `enp3s0` with your network interface.

The application continuously monitors supported network traffic and displays security alerts when detection thresholds are reached.

Press `Ctrl+C` to stop monitoring.

## Intrusion Detection Rules

Detection settings can be modified in `config/ids_rules.conf`.

| Detection | Default Threshold | Time Window |
|---|---|---|
| Port Scan | 20 unique ports | 10 seconds |
| SYN Flood | 100 SYN packets | 5 seconds |
| ICMP Flood | 100 echo requests | 5 seconds |

These thresholds are intended for experimentation and may require adjustment depending on network conditions.

## Testing

The project includes basic tests for packet parsing and intrusion detection.

Compile and run the detection tests:

```bash
g++ -std=c++17 -Iinclude \
    tests/test_detection.cpp \
    src/DetectionEngine.cpp \
    src/PacketParser.cpp \
    -o build/test_detection

./build/test_detection
```

Tests cover port scanning, SYN flooding, ICMP flooding, alert cooldowns, and sliding time windows.

## Current Limitations

- Supports Ethernet and IPv4 packet parsing.
- Does not currently support IPv6 or IP fragment reassembly.
- Detection uses basic rule-based thresholds and may produce false positives.
- Alerts are displayed in the terminal rather than saved to files.
- Intended for learning and testing, not production deployment.

## Future Improvements

- JSON and CSV security alert logging
- Network traffic statistics
- IPv6 protocol support
- Offline PCAP file analysis
- Improved detection rules and connection tracking
- Automatic cleanup of inactive traffic histories

## Project Purpose

This project was developed to gain hands-on experience with network programming, packet analysis, intrusion detection, and cybersecurity using C++.
