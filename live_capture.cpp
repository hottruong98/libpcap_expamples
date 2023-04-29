// Compile with: g++ -o liveCapture live_capture.cpp -lpcap
// Execute with: sudo ./liveCapture
#include <iostream>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

// How to open a network device for live capturing & capture a single packet
int main(int argc, char *argv[]) {
    char *device;
    char error_buff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; // 10s

    device = pcap_lookupdev(error_buff);
    if (device == NULL) {
        std::cout << "Error finding device: " << error_buff << std::endl;
        return 1;
    }
    std::cout << "...Gonna capture device " << device << std::endl;
    // OPEN device for live capture
    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, error_buff);
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL) {
        std::cout << "No packet found" << std::endl;
        return 2;
    }

    print_packet_info(packet, packet_header);
    return 0;
}
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length: %d\n", packet_header.len);
}