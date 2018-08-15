#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include "convert_type.h"

using namespace std;

class parse{
private:
    char *interface;
    uint8_t attacker_mac[6];
    uint32_t attacker_ip;
    uint8_t broadcast[6];
    pcap_t *pcd;
public:
    parse(int argc, char* argv[]);
    void check_argc(int argc);
    void print_packet(uint8_t *packet, int length);
    char *using_interface();
    void parse_data_in_linux();
    void get_attacker_mac(uint8_t mac[6]);
    void get_attacker_ip(char ip[16]);
    void get_pcap_handle(pcap_t *pcd);
    uint8_t *using_attacker_mac();
    uint32_t using_attacker_ip();
    uint8_t *using_broadcast();
    void show_packet(uint8_t *packet, int length);
    pcap_t * using_pcap_handle();
};

#endif // PARSE_H
