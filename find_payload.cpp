// compile with: g++ -o findPayload find_payload.cpp -lpcap
// execute with: sudo ./findPayload
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
int main(int argc, char* argv[]) {
    pcap_t* handle;
    char* device = "enp2s0";
    char error_buff[PCAP_ERRBUF_SIZE];
    int snapshot_len = 1024; // How many bytes to capture from each packet
    int promicuous = 0;
    int timeout = 10000; // 10s
    int total_packet_count = 200; // End the loop after this many packets are captured
    u_char* my_args = NULL;

    handle = pcap_open_live(device, snapshot_len, promicuous, timeout, error_buff);
    pcap_loop(handle, total_packet_count, my_packet_handler, my_args);
    return 0;
}
void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    // First, make sure we have an IP packet
    struct ether_header* ether_hdr;
    ether_hdr = (struct ether_header*) packet;
    if (ntohs(ether_hdr->ether_type) != ETHERTYPE_IP) {
        std::cout << "Not an IP packet.  Skipping...\n\n";
        return;
    }
    printf("Packet's captured length: %d bytes\n", header->caplen);
    printf("Packet's total length: %d bytes\n", header->len); // total packet length, may > what we've currently captured (if snapshot length is too small)
    
    // Pointers to starting point of various headers
    const u_char* ip_hdr;
    const u_char* tcp_hdr;
    const u_char* udp_hdr;
    const u_char* payload;

    // Header lengths in bytes
    int ether_hdr_len = ETHER_HDR_LEN; // always 14
    int ip_hdr_len;
    int tcp_hdr_len;
    int udp_hdr_len;
    int payload_len;

    // Find start of IP header
    ip_hdr = packet + ether_hdr_len;
    ip_hdr_len = (*ip_hdr) & 0x0F; // 1st byte of ip header is [IP version and header length] => half byte for len
    ip_hdr_len *= 4; // HDL field counts 32-bit words, we must x4 to convert to byte count
    printf("IHL in bytes: %d\n", ip_hdr_len);

    // Check protocol (TCP/UDP) on 10th byte of IP header
    u_char protocol = *(ip_hdr + 9);
    if (protocol != IPPROTO_TCP) {
        std::cout << "Not a TCP packet. Skipping...\n\n";
        return;
    }

    // Find start of TCP header
    tcp_hdr = packet + ether_hdr_len + ip_hdr_len;
    tcp_hdr_len = ((*(tcp_hdr + 12)) & 0xF0) >> 4; // first half (4 bits data offset) of 13th byte 
    tcp_hdr_len *= 4; // the above result counts 32-bit words -> x4 to convert to byte count
    printf("TCP header length in bytes: %d\n", tcp_hdr_len);

    // Add up all header sizes to find the payload offset
    int total_hdr_size = ether_hdr_len + ip_hdr_len + tcp_hdr_len;
    printf("Size of all headers combined: %d bytes\n", total_hdr_size);
    payload_len = header->caplen - total_hdr_size;
    printf("Payload size: %d bytes\n", payload_len);
    payload = packet + total_hdr_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    return;
}