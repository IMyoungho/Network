#include "parse.h"

using namespace std;

parse::parse(int argc, char*argv[]){
    this->interface=argv[1];
    check_argc(argc);
}
void parse::check_argc(int argc){
    if(argc!=2){
        cout << "<usage> : <Interface>" << endl;
        exit(1);
    }
}
char* parse::using_interface(){
    return this->interface;
}
void parse::parsing_in_packet(cal_checksum *cc)
{
    pcap_t *pcd;
    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(this->using_interface(), BUFSIZ, 1, 1, errbuf);
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
                        cc->get_pesudo(udpchecksum);
                        uint16_t checksum=cc->checksum(udpchecksum);
                        cout << hex << "udp checksum = 0x" << checksum << endl;
                    }
                    else if(ip->protocol==0x06)
                    {
                        struct tcphdr *tp = (struct tcphdr*)(packet+sizeof(struct ether_header)+ip->ihl*4);
                        cc->get_tcphdr(tp);
                        cc->get_pesudo(tcpchecksum);
                        uint16_t checksum=cc->checksum(tcpchecksum);
                        cout << hex << "tcp checksum = 0x" << checksum << endl;
                    }
                    else if(ip->protocol==0x01)
                    {
                        struct icmphdr *icp = (struct icmphdr*)(packet+sizeof(struct ether_header)+ip->ihl*4);
                        cc->get_icmphdr(icp);
                        uint16_t checksum=cc->checksum(icmpchecksum);
                        cout << hex << "icmp checksum = 0x" << checksum << endl;
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
                pcd = pcap_open_live(this->using_interface(), BUFSIZ, 1 , 1, errbuf);
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

