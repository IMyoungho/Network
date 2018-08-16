#include "module_r.h"
void finish_packet(parse *ps){ // 끝내기위해서 보냄.. 나에게 더이상 패킷이 안들어오면 정지되지않기때문에 -> 나중에 수정이 필요할듯..
    uint8_t packet[42];
    struct ether_header ep;
    struct arp_header ap;
    struct using_arp_type_data arp_assist;
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pd=pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
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
    ap.dst_ip=ps->using_attacker_ip();
    memcpy(ap.dst_mac,ps->using_broadcast(),6);
    memcpy(packet,(uint8_t *)&ep,sizeof(ether_header));
    memcpy(packet+sizeof(ether_header), (uint8_t*)&ap, sizeof(arp_header));
    sleep(3);
    pcap_sendpacket(pd,packet,42);
    cout << "[!] Sending finish packet" << endl;
}

void receive_arp_packet(parse *ps, map<keydata,valuedata>data_map){
    map<keydata,valuedata>::iterator data_it;
    keydata k;
    valuedata v;
    int ret;
    const uint8_t *packet;
    struct pcap_pkthdr *pkthdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);

    time_t start_time = time(&start_time);
    time_t end_time=0;

    thread finish(finish_packet,ps);

    while(end_time-start_time<=2){  //insert stop function !!
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        time(&end_time);
        switch (ret)
        {
            case 1:
            {
                struct ether_header *ep= (struct ether_header*)packet;
                packet+=sizeof(ether_header);
                if(ep->ether_type==ntohs(ETHERTYPE_ARP))
                {
                    struct arp_header *ap = (struct arp_header*)packet;
                    if(ap->dst_ip==ps->using_attacker_ip() && ap->src_ip!=ps->using_attacker_ip())//not mymac(attacker)
                    {
                        memcpy(k.mac,ap->src_mac,6);
                        v.ip=ap->src_ip;
                        //cout << "ARP packet is coming" << endl;
                        //ps->show_packet((uint8_t*)packet,42);
                        if((data_it = data_map.find(k)) != data_map.end()){
                          //exist data
                        }
                        else{ //new data map insert
                            data_map.insert(pair<keydata, valuedata>(k,v));
                            cout << " [+] R E G I S T R A T I O N" << endl;

                        }
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
    finish.join();
    cout << "receive finsih" << endl;
}


void send_scan_packet(parse *ps){ //map을 인자로 make_arp_scanning? function name??
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
}
