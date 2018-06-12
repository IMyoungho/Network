#ifndef MOVE_PACKET_H
#define MOVE_PACKET_H
#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "parse.h"

using namespace std;

void take_off(parse *ps);
#endif // MOVE_PACKET_H
