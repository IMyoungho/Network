#ifndef COME_PACKET_H
#define COME_PACKET_H
#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>

#include "parse.h"

using namespace std;

void come_packet(parse *ps);
#endif // COME_PACKET_H
