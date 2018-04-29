#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
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
class parse {
private:
    char *interface;
    uint8_t attacker_mac[6];
    uint32_t attacker_ip;
    uint8_t attacker_dhcp_mac[6];
    uint32_t attacker_dhcp_ip;
    uint8_t  client_mac[6];
    uint8_t *dhcp_data;
    int dhcp_data_length;
    uint8_t *dhcp_packet;
    int dhcp_length;
    uint16_t transaction_id;
    uint8_t *arp_packet;
    int arp_length;
public:
    int pre_packet_length;
    uint8_t broadcast[6];
    uint8_t allpacket[6];
    uint8_t origin_dhcp_mac[6];
    uint32_t origin_dhcp_ip;
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    void get_my_mac(uint8_t mac[6]);
    void get_my_ip(char ip[16]);
    void parse_data_in_linux();
    char* using_interface();
    uint8_t *using_broadcast();
    uint8_t *using_allpacket();
    uint8_t *using_attacker_dhcp_server_mac();
    uint32_t *using_attacker_dhcp_server_ip();
    uint8_t *using_normal_dhcp_mac();
    uint32_t *using_normal_dhcp_ip();
    uint8_t *using_client_mac();
    uint32_t *using_client_ip();

    void parse_normal_dhcp_mac(uint8_t mac[6]);
    void parse_normal_dhcp_ip(uint32_t ip);
    void parse_client_mac(uint8_t mac[6]);
    void parse_client_ip(uint32_t ip);
    void make_dhcp_arr_space(int size);
    void get_dhcp_data_length(int length);
    void get_dhcp_data(uint8_t *packet);
    void make_dhcp_length(int size);
    void make_dhcp_packet(uint8_t *packet, int length, bool pointer);
    uint8_t *using_dhcp_data();
    int using_dhcp_data_length();
    uint8_t *using_dhcp_packet();
    int using_dhcp_length();
    void show_dhcp_packet();
    void make_arp_packet();
    void parse_transaction_id(uint16_t id);
    uint16_t *using_transaction_id();
    uint8_t *using_arp_packet();
    int using_arp_packet_length();
};

#endif // PARSE_H
