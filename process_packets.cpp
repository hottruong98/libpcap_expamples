// compile with: g++ -o processPacket process_packets.cpp -lpcap
// execute with: sudo ./processPacket
#include <iostream>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(struct pcap_pkthdr packet_header, const u_char *packet_body);

int main(int argc, char *arcv[]) {
    char *device;
    char error_buff[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 10000; //10s

    device = pcap_lookupdev(error_buff);
    if (device == NULL) {
        std::cout << "Error finding device: " << error_buff << std::endl;
        return 1;
    }
    std::cout << "...gonna capture device " << device << std::endl;
    // Open device for live capture
    // pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
    handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buff);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buff);
        return 2;
    }

    int packet_num = 0; // capture ulimited packets
    u_char *callback_args = NULL; // no arguments to the my_packet_handler() function
    pcap_loop(handle, packet_num, my_packet_handler, callback_args);
    return 0;
}
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    print_packet_info(*header, packet); // <*header> means value at the address the pointer <header> is pointing to
    return;
}
void print_packet_info(struct pcap_pkthdr packet_header, const u_char *packet_body) { // variable <packet_header> = <*header> (with <header> is the pointer)
    printf("Packet capture length: %d\n", packet_header.caplen); 
    printf("Packet total length  : %d\n", packet_header.len);
}