#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include "convert_type.h"
#include "cal_checksum.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define DRONE_PORT 8889
#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2
#define icmpchecksum 3

#define upexcute 11
#define downexcute 12
#define forwardexcute 13
#define backexcute 14
#define leftexcute 15
#define rightexcute 16
using namespace std;
class cal_checksum;
class parse{
private:
    char *interface;
    uint8_t drone_mac[6];
    uint32_t drone_ip;
    uint32_t myip;
public:
    uint8_t common[34];
    uint8_t command[49];
    uint8_t takeoff[49];
    uint8_t landing[46];
    uint8_t up[47];
    uint8_t down[49];
    uint8_t forward[52];
    uint8_t back[49];
    uint8_t left[49];
    uint8_t right[50];

    uint8_t up_excute[54];
    uint8_t down_excute[55];
    uint8_t forward_excute[54];
    uint8_t back_excute[55];
    uint8_t left_excute[55];
    uint8_t right_excute[54];

    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    void make_common_packet(cal_checksum *cc);
    void make_excute(ether_header *ep, iphdr *ip, udphdr *up, cal_checksum *cc, int type);
    void make_command(ether_header*ep, iphdr *ip, udphdr*up, cal_checksum *cc);
    void make_take_off(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_landing(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_up(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_down(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_forward(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_back(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_left(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_right(ether_header *ep, iphdr *ip, udphdr *up, cal_checksum *cc);
};

#endif // PARSE_H
