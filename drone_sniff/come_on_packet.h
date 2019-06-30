#ifndef COME_ON_PACKET_H
#define COME_ON_PACKET_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include "parse.h"

void come_on_packet(parse *ps);
#endif // COME_ON_PACKET_H
