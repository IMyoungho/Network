#ifndef REPLAY_NORMAL_PACKET_H
#define REPLAY_NORMAL_PACKET_H
#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "parse_data.h"
#include "make_send_reply_packet.h"

using namespace std;

void relay_normal_packet(parse_data *parse,pcap_t *ph);
#endif // REPLAY_NORMAL_PACKET_H
