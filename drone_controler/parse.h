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

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

class parse{
private:
    char *interface;
    uint32_t drone_ip;
    uint32_t device_ip;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    void come_on_packet();
};

#endif // PARSE_H
