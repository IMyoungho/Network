#ifndef SEND_PACKET_H
#define SEND_PACKET_H
#include "parse.h"
#include <pcap.h>
void send_arp(parse *ps);
void send_dhcp_offer(parse *ps);
#endif // SEND_PACKET_H
