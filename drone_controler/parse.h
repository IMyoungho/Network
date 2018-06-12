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
using namespace std;
class cal_checksum;
class parse{
private:
    char *interface;
    uint8_t drone_mac[6];
    uint32_t drone_ip;

public:
    uint8_t common[34];
    uint8_t takeoff[49];
    uint8_t landing[1];
    uint8_t up[47];
    uint8_t down[49];
    uint8_t go[52];
    uint8_t back[49];
    uint8_t left[49];
    uint8_t right[50];
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    void make_common_packet(cal_checksum *cc);
    void make_excute(ether_header *ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_take_off(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_landing(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_up(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_down(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_go(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_back(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_left(ether_header*ep, iphdr *ip, udphdr *up, cal_checksum *cc);
    void make_right(ether_header *ep, iphdr *ip, udphdr *up, cal_checksum *cc);
};

#endif // PARSE_H
