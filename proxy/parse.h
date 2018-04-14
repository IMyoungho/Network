#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "cal_checksum.h"
#include "convert_type.h"

#define MTU 1500
#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2
#define icmpchecksum 3

using namespace std;
class cal_checksum;
class parse {
private:
    char *interface;
    uint8_t my_mac[6];
    uint32_t my_ip;
    uint8_t *send_packet;
    int send_packet_length;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc);
    char* using_interface();
    void get_my_mac(uint8_t mac[6]);
    void get_my_ip(char ip[16]);
    uint8_t *using_my_mac();
    uint32_t using_my_ip();
    void parse_data_in_linux();
    void get_send_packet_length(int length);
    int using_send_packet_length();
    void make_send_packet(iphdr *ipd, uint8_t *data);
    uint8_t *using_send_packet();
};
#endif // PARSE_H
