#ifndef MAKE_SEND_REPLY_PACKET_H
#define MAKE_SEND_REPLY_PACKET_H
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "parse_data.h"

using namespace std;

void send_reply_arp(pcap_t* pcd, uint8_t packet[42],int packet_len);
void make_send_reply_packet(parse_data *parse);
#endif // MAKE_SEND_REPLY_PACKET_H
