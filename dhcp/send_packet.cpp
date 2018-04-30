#include "send_packet.h"
#include "detect_packet.h"

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
    atomic<bool> run{true};
    thread detect(detect_tftp_packet,ps,ref(run));
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    while(run)
    {
        cout << ">> Send DHCP Packet !!" << endl;
        pcap_sendpacket(pcd,(const u_char*)ps->using_dhcp_packet(),ps->using_dhcp_length()); //temp
        sleep(1);
    }
    if(detect.joinable()==true)
       detect.join();
}


