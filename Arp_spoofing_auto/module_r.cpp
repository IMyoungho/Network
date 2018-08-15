#include "module_r.h"

void make_arp_packet(parse *ps){ //map을 인자로 make_arp_scanning? function name??
    uint8_t arp_packet[42];
    struct ether_header ep;
    struct arp_header ap;
    struct using_arp_type_data arp_assist;

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

    char errbuf[PCAP_ERRBUF_SIZE];
    ps->get_pcap_handle(pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf));
    uint32_t scanning_ip=(ps->using_attacker_ip() & 0xffffff);

    for(int i = 2; i< 255; i++){
        ap.dst_ip=scanning_ip + (i << 24);
        memcpy(arp_packet+sizeof(ether_header), (uint8_t*)&ap, sizeof(arp_header));
        pcap_sendpacket(ps->using_pcap_handle() ,arp_packet, sizeof(arp_packet));
        cout << "0x"<< hex << htonl(((ps->using_attacker_ip() & 0xffffff)) + (i<<24)) << endl;
        sleep(0.01);
    }

    pcap_close(ps->using_pcap_handle());
    ps->show_packet(arp_packet,42);
}
