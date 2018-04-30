#ifndef SEND_PACKET_H
#define SEND_PACKET_H
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <thread>
#include <pthread.h>
#include "parse.h"
#include <atomic>
using namespace std;

void send_arp(parse *ps);
void send_dhcp_offer(parse *ps);
#endif // SEND_PACKET_H
