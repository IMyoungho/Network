#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include "convert_type.h"

using namespace std;
#pragma pack(push,1)
struct arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_size;
    uint8_t  protocol_size;
    uint16_t opcode;
    uint8_t  src_mac[6];
    uint32_t src_ip;
    uint8_t  dst_mac[6];
    uint32_t dst_ip;
};
struct using_arp_type_data
{
    uint16_t ether_arp_type = htons(0x0806);
    uint16_t hardware_type = htons(0x0001);
    uint16_t ipv4_type = htons(0x0800);
    uint8_t  hardware_size = 0x06;
    uint8_t  protocol_size = 0x04;
    uint16_t request_opcode  = htons(0x0001);
    uint16_t reply_opcode  = htons(0x0002);
};
#pragma pack(pop)
class parse {
private:
    char * interface;
    uint8_t attack_mac[6];
    uint32_t attack_ip;
    uint8_t broadcast[6];
public:
    parse(int argc, char *argv[]);
    char* using_interface();
    void check_argc(int argc);
    void get_attacker_mac(uint8_t mac[6]);
    void get_attacker_ip(char ip[16]);
    uint8_t *using_attacker_mac();
    uint32_t using_attacker_ip();
    uint8_t *using_broadcast();
    void parse_data_in_linux();
    void make_arp_packet();
    void show_packet(uint8_t *packet, int length);
    void choice_frame();
};

#endif // PARSE_H
