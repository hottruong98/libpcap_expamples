// Compile with: g++ -o getDeviceInfo get_device_info.cpp -lpcap
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *device;
    char readable_ip[16];
    char readable_subnet_mask[16]; // https://stackoverflow.com/questions/60384468/why-is-the-buffer-size-in-inet-ntoa-18
    uint32_t ip_raw;
    uint32_t subnet_mask_raw;
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr address; // in_addr = uint32_t

    // Find a device
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        std::cout << error_buffer << std::endl;
        return 1;
    }
    // Get device info
    lookup_return_code = pcap_lookupnet(device, &ip_raw, &subnet_mask_raw, error_buffer);
    if (lookup_return_code == -1) {
        std::cout << error_buffer << std::endl;
        return 1;
    }
    // Get IP in human readable form
    address.s_addr = ip_raw;
    strcpy(readable_ip, inet_ntoa(address));
    if (readable_ip == NULL) {
        perror("inet_ntoa"); // print error
        return 1;
    }
    // Get subnet mask in human readable form
    address.s_addr = subnet_mask_raw;
    strcpy(readable_subnet_mask, inet_ntoa(address)); // use strcpy instead of assignment to prevent overwriting content of ip pointer
    if (readable_subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    printf("Device: %s\n", device);
    printf("IP address: %s\n", readable_ip);
    printf("subnet mask: %s\n", readable_subnet_mask);

    return 0;
}