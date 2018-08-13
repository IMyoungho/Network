#ifndef SEND_PACKET_H
#define SEND_PACKET_H
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <pcap.h>
#include "parse_data.h"

using namespace std;

uint8_t * send_receive_packet(parse_data *parse, uint8_t *sendpacket, int sendpacket_length);
#endif // SEND_PACKET_H
