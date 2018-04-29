#include "send_packet.h"

void send_arp(parse *ps){
    ps->make_arp_packet();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    while(true)
    {
        cout << ">>Send Arp Packet" << endl;
        pcap_sendpacket(pcd,(const u_char*)ps->using_arp_packet(),ps->using_arp_packet_length());
    }
}
void send_dhcp_offer(parse *ps){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pct;
    pct=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    while(true)
    {
        cout << ">> Send DHCP Packet !!" << endl;
        pcap_sendpacket(pct,(const u_char*)ps->using_dhcp_packet(),ps->using_dhcp_length()); //temp
    }
}


