#ifndef PARSE_DATA_H
#define PARSE_DATA_H
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>

using namespace std;

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
class parse_data{
private:
    char *interface;
    uint8_t attack_mac[6];
    uint32_t attack_ip;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
    uint8_t send_arp_reply_packet[42];
    int send_arp_length;
    pcap_t * used_pcap_t;
public:
    parse_data(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char* using_interface();
    void get_target_mac(uint8_t mac[6]);
    void get_sender_mac(uint8_t mac[6]);
    void get_attacker_mac(uint8_t mac[6]);
    void get_attacker_ip(char ip[16]);
    struct using_arp_type_data uat;
    uint8_t *using_attack_mac();
    uint32_t *using_attack_ip();
    uint8_t *using_sender_mac();
    uint32_t *using_sender_ip();
    uint8_t *using_target_mac();
    uint32_t *using_target_ip();
    void get_arp_reply_packet_data(uint8_t packet[42], int packet_len, pcap_t *pcaphandle);
    uint8_t *using_send_arp_reply_packet();
    int using_send_arp_reply_length();
    pcap_t *using_send_arp_reply_pcaphandle();
};


#endif // PARSE_DATA_H
