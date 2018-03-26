#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <string>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "parse.h"
#include "detect_parsing_packet.h"
#include "send_dhcp_offer.h"

using namespace std;
//checksum gogo
int main(int argc, char *argv[])
{
    parse ps(argc,argv);
    detect_parsing_packet(&ps);
    send_dhcp_offer(&ps);
    return 0;
}
