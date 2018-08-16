#include "module_r.h"

void receive_arp_packet(parse *ps){
    int ret;
    const uint8_t *packet;
    struct pcap_pkthdr *pkthdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
    while(true){
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (ret)
        {
            case 1:
            {
                //cout << "Packet is comming" << endl;
                struct ether_header *ep= (struct ether_header*)packet;
                packet+=sizeof(ether_header);
                if(ep->ether_type==ntohs(ETHERTYPE_ARP))
                {
                    struct arp_header *ap = (struct arp_header*)packet;
                    if(ap->dst_ip==ps->using_attacker_ip())
                    {
                        cout << "ARP packet is comssming" << endl;
                        ps->show_packet((uint8_t*)packet,42);
                    }
                }
            }
            break;
            case 0:
                continue;
            case -1:{
                cout << ">> Error \n";
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:{
                cout << "EOF\n";
            }
            break;
            default:
            break;
        }
    }
}


void make_arp_packet(parse *ps){ //map을 인자로 make_arp_scanning? function name??
    uint8_t arp_packet[42];
    struct ether_header ep;
    struct arp_header ap;
    struct using_arp_type_data arp_assist;

    pcap_t *ppd;
    char errbuf[PCAP_ERRBUF_SIZE];
    ppd=pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);

    memcpy(ep.ether_shost,ps->using_attacker_mac(),6);
    memcpy(ep.ether_dhost,ps->using_broadcast(),6);
    ep.ether_type=arp_assist.ether_arp_type;
    ap.hardware_type=arp_assist.hardware_type;
    ap.protocol_type=arp_assist.ipv4_type;
    ap.hardware_size=arp_assist.hardware_size;
    ap.protocol_size=arp_assist.protocol_size;
    ap.opcode=arp_assist.request_opcode;
    memcpy(ap.src_mac,ps->using_attacker_mac(),6);
    ap.src_ip=ps->using_attacker_ip();
    memcpy(ap.dst_mac,ps->using_broadcast(),6);
    memcpy(arp_packet,(uint8_t *)&ep,sizeof(ether_header));

    uint32_t scanning_ip=(ps->using_attacker_ip() & 0xffffff);

    for(int i = 2; i< 255; i++){
        ap.dst_ip=scanning_ip + (i << 24);
        memcpy(arp_packet+sizeof(ether_header), (uint8_t*)&ap, sizeof(arp_header));
        pcap_sendpacket(ppd, arp_packet, sizeof(arp_packet));
        //cout << "0x"<< hex << htonl(((ps->using_attacker_ip() & 0xffffff)) + (i<<24)) << endl;
        sleep(0.01);
    }
    pcap_close(ppd);
    //ps->show_packet(arp_packet,42);
}
