#ifndef COME_ON_PACKET_H
#define COME_ON_PACKET_H
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "parse.h"

void come_on_packet(parse *ps)
{
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const u_int8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    while(true)
    {
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (ret)
        {
            case 1:
            {
                cout << "Packet is coming"<<endl;
                int packet_len = pkthdr->len;
                struct ether_header *ep= (struct ether_header*)packet;
                if(ep->ether_type==ntohs(ETHERTYPE_IP))
                {
                    cout << "IP packet is comming" <<endl;
                    struct iphdr *iph = (struct iphdr*)(packet+sizeof(ether_header));
                    if(iph->protocol==0x11)
                    {
                        cout << ">> UDP packet is comming" << endl;
                        struct udphdr *udph = (struct udphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                    }
                    else if(iph->protocol==0x06)
                    {
                        cout << ">> TCP packet is comming" << endl;
                        struct tcphdr *tcph = (struct tcphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                    }
                }
                if(ep->ether_type==ntohs(ETHERTYPE_ARP))
                    cout << "ARP packet is comming" << endl;
            }
            break;
            case 0:
                continue;
            case -1:
            {
                cout << ">> Error \n";
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:
            {
                cout << "EOF\n";
            }
            break;
            default:
            break;
        }
    }
}
#endif // COME_ON_PACKET_H
