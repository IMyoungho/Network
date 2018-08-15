#ifndef ARP_HEADER_H
#define ARP_HEADER_H
#include <iostream>
#include <arpa/inet.h>

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
#endif // ARP_HEADER_H
