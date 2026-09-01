#ifndef ANOMALY_DETECTION_H
#define ANOMALY_DETECTION_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

struct AnomAlert {
    std::string type;     // "PORT_SCAN" etc.
    std::string src_ip;   // "192.168.1.10"
    std::string desc;     // more details
};

class AnomalyDetector {
public:
    AnomalyDetector() = default;

    // Feed packet info to the detector
    void feed_packet(uint32_t src_ip_net, uint16_t dest_port, uint64_t ts_sec);

    // Check if any alerts should fire right now
    std::vector<AnomAlert> check_now(uint64_t ts_sec);

private:
    struct Entry {
        uint64_t ts_sec;
        uint16_t port;
    };

    // For each source IP → store ports accessed in recent seconds
    std::unordered_map<uint32_t, std::vector<Entry>> recent;

    // Configuration (tuning)
    const uint32_t WINDOW = 5;            // time window in seconds
    const size_t PORT_SCAN_UNIQUE = 20;   // threshold for alert

    void prune_old(uint32_t src_ip, uint64_t now);

    static std::string ip_to_string(uint32_t ip_net);
};

#endif // ANOMALY_DETECTION_H
