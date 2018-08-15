#ifndef MODULE_R_H
#define MODULE_R_H
#include <iostream>
#include <netinet/ether.h>
#include <string.h>
#include <unistd.h>
#include "arp_header.h"
#include "parse.h"

using namespace std;

void make_arp_packet(parse *ps);
#endif // MODULE_R_H
