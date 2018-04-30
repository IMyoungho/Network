#ifndef DETECT_PACKET_H
#define DETECT_PACKET_H
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <atomic>
#include "cal_checksum.h"
#include "dhcp_header.h"
#include "parse.h"

#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2
#define icmpchecksum 3
#define OUT_OF_RANGE 65536
#define MTU 1500

bool detect_parsing_packet(parse *ps);//void -> bool
void detect_tftp_packet(parse *ps, atomic<bool> &run);

#endif // DETECT_PACKET_H
