#include "come_packet.h"

using namespace std;

int command=0; // go(command) 패킷이 없으면 방향 패킷이 있어도 움직이지 않음
int foward=0, back=0, left=0, right=0;

void come_packet(parse *ps){
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
                int packet_len = pkthdr->len;
                struct ether_header *ep= (struct ether_header*)packet;
                if(ep->ether_type==ntohs(ETHERTYPE_IP) && memcmp(ep->ether_dhost,ps->using_drone_mac(),6)==0)
                {
                    struct iphdr *iph = (struct iphdr*)(packet+sizeof(ether_header));
                    if(iph->protocol==0x11)
                    {
                        cout << ">> Drone packet is comming" << endl;
                        struct udphdr *udph = (struct udphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                        packet+=sizeof(ether_header)+sizeof(iphdr)+sizeof(udphdr);
                        char check_direct = *packet;
                        if(udph->dest==0x22B9){
                            switch(check_direct){
                            //modi here
                            }
                        }
                    }
                }
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
