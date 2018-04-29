#ifndef SEND_PACKET_H
#define SEND_PACKET_H
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include "parse.h"

using namespace std;

void send_arp(parse *ps);
void send_dhcp_offer(parse *ps);
#endif // SEND_PACKET_H
