#include "pcap_reader.h"
#include "processor.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>

using namespace std;

// PCAP Global Header (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// PCAP Packet Header (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

void start_pcap_reader(const string &filename) {
    cout << "[PCAP] Opening file: " << filename << endl;

    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cout << "[ERROR] Could not open PCAP file.\n";
        return;
    }

    // Read global header
    PcapGlobalHeader gh;
    file.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    if (!file) {
        cout << "[ERROR] Failed reading global header.\n";
        return;
    }

    cout << "[PCAP] Global Header Read." << endl;

    int packetCount = 0;

    // Packet loop
    while (true) {
        PcapPacketHeader ph;

        // Try reading packet header
        file.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (!file) break; // EOF or error

        if (ph.incl_len == 0) {
            // empty/weird packet
            continue;
        }

        // Read packet payload
        char* buf = new char[ph.incl_len];

        file.read(buf, ph.incl_len);
        if (!file) {
            delete[] buf;
            break;
        }

        packetCount++;

        // Process actual bytes
        process_packet(buf, ph.incl_len);

        delete[] buf;
    }

    cout << "[PCAP] Finished reading packets. Total: " << packetCount << endl;
}
