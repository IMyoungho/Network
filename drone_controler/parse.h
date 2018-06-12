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

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define DRONE_PORT 8889
using namespace std;

class parse{
private:
    char *interface;
    uint8_t drone_mac[6];
    uint32_t drone_ip;

public:
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    void make_packet();
    uint32_t using_drone_ip();
    uint8_t *using_drone_mac();
};

#endif // PARSE_H
