#ifndef PARSE_PACKET_H
#define PARSE_PACKET_H
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include "parse.h"
#include "cal_checksum.h"

#define MTU 1500
#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2

void parsing_in_packet(parse *ps, cal_checksum *cc)
{
    pcap_t *pcd;
    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(ps->using_interface(), BUFSIZ, 1, 1, errbuf);
    while(true)
    {
        res=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (res)
        {
            case 1:
            {
                struct ether_header *ep = (struct ether_header *)packet;
                if(ep->ether_type==ntohs(0x0800))
                {
                    struct iphdr *ip = (struct iphdr *)(packet+sizeof(struct ether_header));
                    cc->get_iphdr(ip);
                    uint16_t checksum=cc->checksum(ipchecksum);
                    cout << hex << "ip checksum = 0x" << checksum << endl;
                    if(ip->protocol==0x11)
                    {
                        struct udphdr *up = (struct udphdr*)(packet+sizeof(struct ether_header)+ip->ihl*4);
                        cc->get_udphdr(up);
                        cc->get_udp_pesudo();
                        uint16_t checksum=cc->checksum(udpchecksum);
                        cout << hex << "udp checksum = 0x" << checksum << endl;
                    }
                }
            }
            break;
            case 0:
                continue;
            case -1:
            {
                printf(">> Error!!\n");
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:
            {
                printf("EOF");
            }
            break;
            default:
                break;
        }
    }
}
#endif // PARSE_PACKET_H
