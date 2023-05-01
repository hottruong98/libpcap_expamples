// compile with: g++ -o offlineCapture offline_capture.cpp -lpcap
// execute with: sudo ./offlineCapture
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void my_packet_handler(u_char* my_args, const struct pcap_pkthdr* header, const u_char* packet);
int main(int argc, char* argv[]) {
    pcap_t* handle;
    const char pcap_file[] = "/home/hottruong/myProject/catkin_ws/src/ars430_ros_publisher/recorded_pcap/ARS430_sample_parking.pcapng";
    char error_buff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, error_buff);
    if (handle == NULL) {
        std::cout << "??\n";
        return 1;
    }

    int packet_num = 0;
    pcap_loop(handle, packet_num, my_packet_handler, NULL);
    return 0;
}
void my_packet_handler(u_char* my_args, const struct pcap_pkthdr* header, const u_char* packet) {
    
    return;
}