#include "send_packet.h"

uint8_t * send_receive_packet(parse_data *parse, uint8_t *sendpacket, int sendpacket_length){
    //**************************send packet!!**************************
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd = pcap_open_live(parse->using_interface(), BUFSIZ, 0 , 1, errbuf);
    if(pcd==nullptr){
        printf("%s\n",errbuf);
        exit(1);
    }
    pcap_sendpacket(pcd,(u_char*)sendpacket,sendpacket_length);
    cout << " >> Ask Gatewaymac packet is Sending !!" << endl;

    //*************************receive packet!!************************
    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int res;
    uint8_t *get_mac=new uint8_t[6];
    while((res=pcap_next_ex(pcd, &pkthdr, &packet))>=-2){
        if(res==1){
            while(pkthdr->len>0){
                cout << " >> Answer receive packet" <<endl;
                struct ether_header *ep=(struct ether_header*)packet;
                if(ep->ether_type==htons(0x0806)){
                    packet+=sizeof(ether_header);
                    struct arp_header *ah=(struct arp_header*)packet;
                    if(ah->opcode==htons(0x0002)){
                        memcpy(get_mac,ep->ether_shost,6);
                        pcap_close(pcd);
                        break;
                    }
                }
            }
            break;
        }
        else if(res==0)
            continue;
        else if(res==-1){
            printf(">> Error!!\n");
            pcap_close(pcd);
            sleep(1);
            pcd = pcap_open_live(parse->using_interface(), BUFSIZ, 0 , 1, errbuf);
        }
        else if(res==-2)
            printf("EOF");
        else
            break;
    }
    return get_mac;
}
