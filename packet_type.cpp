// compile with: g++ -o packetType packet_type.cpp -lpcap
// execute with: sudo ./packetType
#include <iostream>
#include <pcap.h>
#include <netinet/in.h> // Internet Protocol family
#include <net/ethernet.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char *packet);
int main(int argc, char *argv[]) {
    pcap_t *handle;
    char *device = "enp2s0";
    char error_buff[PCAP_ERRBUF_SIZE];
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;
    int packet_num = 1; // receive only 1 packet
    u_char *callback_args = NULL;

    handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buff);
    pcap_loop(handle, packet_num, my_packet_handler, callback_args);
    pcap_close(handle);

    return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header; // MAC header (14 bytes)
    eth_header = (struct ether_header *) packet; // treat pointer to packet as pointer to MAC header
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        std::cout << "IP" << std::endl;
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        std::cout << "ARP" << std::endl;
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        std::cout << "Reverse ARP" << std::endl;
    }
}