#ifndef PACKET_STRUCTS_H
#define PACKET_STRUCTS_H

#include <cstdint>

#pragma pack(push, 1)

// Ethernet header - 14 bytes
struct EthernetHeader {
    uint8_t dest[6];   // Destination MAC address (6 bytes)
    uint8_t src[6];    // Source MAC address (6 bytes)
    uint16_t type;     // EtherType (2 bytes) - e.g., 0x0800 for IPv4
};

// IPv4 header - 20 bytes minimum (IHL may make it larger)
struct IPv4Header {
    uint8_t version_ihl;   // version (4 bits) + IHL (4 bits)
    uint8_t tos;           // type of service
    uint16_t total_length; // total length (header + data)
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;           // time to live
    uint8_t protocol;      // protocol (6 = TCP, 17 = UDP, 1 = ICMP)
    uint16_t checksum;
    uint32_t src_ip;       // source IP (network byte order)
    uint32_t dest_ip;      // destination IP (network byte order)
};

// TCP header (minimum 20 bytes)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved; // high 4 bits = data offset (in 32-bit words)
    uint8_t flags;                // flags: SYN, ACK, FIN, RST...
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// UDP header (8 bytes)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

#pragma pack(pop)

#endif // PACKET_STRUCTS_H
