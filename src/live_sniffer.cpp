#include "live_sniffer.h"
#include "processor.h"

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // ETH_P_ALL
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

using namespace std;

void start_live_sniffer(const string &interfaceName) {
    cout << "[LIVE] Starting live sniffing on interface: " << interfaceName << endl;

    // 1) Create raw packet socket
    int rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawsock == -1) {
        perror("socket");
        return;
    }

    // 2) Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ-1);

    if (ioctl(rawsock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(rawsock);
        return;
    }
    int ifindex = ifr.ifr_ifindex;

    // 3) Bind socket to the interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(rawsock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(rawsock);
        return;
    }

    // 4) Buffer for incoming packets
    const int BUFSIZE = 65536;
    char *buffer = new char[BUFSIZE];

    cout << "[LIVE] Sniffing... (Press CTRL+C to stop)" << endl;

    // 5) Main capture loop
    while (true) {
        ssize_t n = recvfrom(rawsock, buffer, BUFSIZE, 0, nullptr, nullptr);
        if (n <= 0) continue;

        // Send raw bytes to processor
        process_packet(buffer, static_cast<uint32_t>(n));
    }

    delete[] buffer;
    close(rawsock);
}
