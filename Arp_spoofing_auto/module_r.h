#ifndef MODULE_R_H
#define MODULE_R_H
#include <iostream>
#include <netinet/ether.h>
#include <string.h>
#include <unistd.h>
#include <atomic>
#include <arpa/inet.h>
#include <ctime>
#include <thread>
#include "arp_header.h"
#include "parse.h"
#include "setting_map.h"
#include "keyboard_event.h"

using namespace std;

void receive_arp_packet(parse *ps, map<keydata, valuedata> data_map);
void send_scan_packet(parse *ps);
#endif // MODULE_R_H
