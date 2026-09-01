#include "processor.h"
#include "../include/packet_structs.h"
#include "signature_detection.h"
#include "anomaly_detection.h"
#include "utils.h"

#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <chrono>

using namespace std;

// Singletons for detectors (kept simple)
static SignatureDetector sigdet;
static AnomalyDetector anomdet;
static bool detectors_loaded = false;

// Helper: convert network-order uint32_t IP to dotted string
static string ip_to_string(uint32_t ip_netorder) {
    uint32_t ip = ntohl(ip_netorder);
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

// Ensure detectors (load signatures once)
static void ensure_detectors() {
    if (detectors_loaded) return;
    // Try loading signatures; if missing, signatures will be empty but program continues
    sigdet.load_signatures("config/signatures.txt");
    detectors_loaded = true;
}

void process_packet(const char* data, uint32_t length) {
    // Make sure detectors are ready
    ensure_detectors();

    // 1) Basic size check for Ethernet header
    if (length < sizeof(EthernetHeader)) {
        return;
    }

    // 2) Parse Ethernet header
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t ethType = ntohs(eth->type);
    if (ethType != 0x0800) { // only IPv4 handled for now
        return;
    }

    // 3) Check we have enough for IPv4 header
    if (length < sizeof(EthernetHeader) + sizeof(IPv4Header)) return;
    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(data + sizeof(EthernetHeader));

    uint8_t version = ip->version_ihl >> 4;
    uint8_t ihl_words = ip->version_ihl & 0x0F;
    uint32_t ihl_bytes = ihl_words * 4;
    if (version != 4 || ihl_bytes < 20) return;

    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->src_ip;
    uint32_t dst_ip = ip->dest_ip;

    size_t ip_header_offset = sizeof(EthernetHeader);
    size_t transport_offset = ip_header_offset + ihl_bytes;
    if (length < transport_offset) return;

    // We'll compute payload info per-protocol
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;

    // Current epoch seconds used for anomaly detector timing
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch()).count();

    // ----------------------
    // Handle TCP
    // ----------------------
    if (protocol == 6) { // TCP
        if (length < transport_offset + sizeof(TCPHeader)) return;
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(data + transport_offset);

        uint16_t src_port = ntohs(tcp->src_port);
        uint16_t dst_port = ntohs(tcp->dest_port);

        uint8_t data_offset_words = (tcp->data_offset_reserved >> 4) & 0x0F;
        uint32_t tcp_header_len = data_offset_words * 4;
        if (tcp_header_len < 20) tcp_header_len = 20;

        payload_offset = transport_offset + tcp_header_len;
        payload_len = (payload_offset > length ? 0 : length - payload_offset);

        // Log traffic line
        string tline = "TCP src=" + ip_to_string(src_ip) + ":" + to_string(src_port) +
                       " dst=" + ip_to_string(dst_ip) + ":" + to_string(dst_port) +
                       " totallen=" + to_string(length);
        log_traffic(tline);

        // Signature detection on payload (if any)
        if (payload_len > 0) {
            auto matches = sigdet.match_payload(data + payload_offset, payload_len);
            for (const auto &m : matches) {
                string desc = m.tag + " src=" + ip_to_string(src_ip) + ":" + to_string(src_port) +
                              " dst=" + ip_to_string(dst_ip) + ":" + to_string(dst_port) +
                              " pat=" + m.pattern;
                log_alert(desc);
            }
        }

        // Feed anomaly detector (port scan heuristic)
        anomdet.feed_packet(src_ip, dst_port, now);
        auto anom_alerts = anomdet.check_now(now);
        for (const auto &a : anom_alerts) {
            log_alert(a.type + " src=" + a.src_ip + " desc=\"" + a.desc + "\"");
        }
    }
    // ----------------------
    // Handle UDP
    // ----------------------
    else if (protocol == 17) { // UDP
        if (length < transport_offset + sizeof(UDPHeader)) return;
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(data + transport_offset);

        uint16_t src_port = ntohs(udp->src_port);
        uint16_t dst_port = ntohs(udp->dest_port);

        payload_offset = transport_offset + sizeof(UDPHeader);
        payload_len = (payload_offset > length ? 0 : length - payload_offset);

        string tline = "UDP src=" + ip_to_string(src_ip) + ":" + to_string(src_port) +
                       " dst=" + ip_to_string(dst_ip) + ":" + to_string(dst_port) +
                       " totallen=" + to_string(length);
        log_traffic(tline);

        if (payload_len > 0) {
            auto matches = sigdet.match_payload(data + payload_offset, payload_len);
            for (const auto &m : matches) {
                string desc = m.tag + " src=" + ip_to_string(src_ip) + ":" + to_string(src_port) +
                              " dst=" + ip_to_string(dst_ip) + ":" + to_string(dst_port) +
                              " pat=" + m.pattern;
                log_alert(desc);
            }
        }

        // feed anomaly detector
        anomdet.feed_packet(src_ip, dst_port, now);
        auto anom_alerts = anomdet.check_now(now);
        for (const auto &a : anom_alerts) {
            log_alert(a.type + " src=" + a.src_ip + " desc=\"" + a.desc + "\"");
        }
    }
    // ----------------------
    // Other protocols
    // ----------------------
    else {
        // For now we do minimal handling for others (ICMP etc.)
        // Could extend later.
    }
}
