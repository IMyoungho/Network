#ifndef SEND_DHCP_OFFER_H
#define SEND_DHCP_OFFER_H
#include "parse.h"
#include <pcap.h>

void send_dhcp_offer(parse *ps)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,0,1,errbuf);
    while(true)
    {
        cout << ">> Send DHCP Packet !!" << endl;
        pcap_sendpacket(pcd,(const u_char*)ps->using_dhcp_packet(),ps->using_dhcp_length()); //temp
    }

}
#endif // SEND_DHCP_OFFER_H
