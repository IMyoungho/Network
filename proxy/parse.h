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

#define MTU 1500
#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2
#define icmpchecksum 3

using namespace std;

class parse {
private:
    char *interface;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc);
    char* using_interface();
    void parsing_in_packet(cal_checksum *cc);
};
#endif // PARSE_H
