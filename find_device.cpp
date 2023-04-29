// Compile with: g++ -o find_device find_device.cpp -lpcap
// Run with    : ./find_device
// Result      : Network device found: enp2s0
#include <iostream>
#include <pcap.h>

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // Find a device
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        std::cout << "Error finding device: " << error_buffer << std::endl;
        return 1;
    }
    std::cout << "Network device found: " << device << std::endl;
    return 0;
}

