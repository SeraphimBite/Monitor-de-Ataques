#include <iostream>
#include <string>

#include "pcap_reader.h"
#include "live_sniffer.h"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage:\n";
        cout << "  --pcap <file.pcap>\n";
        cout << "  --live <interface>\n";
        return 1;
    }

    string mode = argv[1];

    if (mode == "--pcap") {
        string filename = argv[2];
        cout << "[MODE] PCAP mode: " << filename << endl;
        start_pcap_reader(filename);
    }
    else if (mode == "--live") {
        string interfaceName = argv[2];
        cout << "[MODE] LIVE mode on interface: " << interfaceName << endl;
        start_live_sniffer(interfaceName);
    }
    else {
        cout << "Invalid mode. Use --pcap or --live." << endl;
        return 1;
    }

    return 0;
}
