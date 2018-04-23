#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <string>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <thread>
#include <pthread.h>
#include "parse.h"
#include "detect_parsing_packet.h"
#include "send_packet.h"

using namespace std;

int main(int argc, char *argv[])
{
    parse ps(argc,argv);
    bool check = detect_parsing_packet(&ps);
    if(check!=true)
        return 0;
    thread arp(send_arp,&ps);
    send_dhcp_offer(&ps);
    if(arp.joinable()==true)
        arp.join();
    return 0;
}
