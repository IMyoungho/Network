#include "ieee80211.h"
#include "come_on_packet.h"

uint8_t video[10000];
int offset=0;
bool start = false;

void showme(uint8_t *packet, int len){
    for(int i=0; i<len; i++)
    {
        if(i%36==0)
            printf("\n");
        printf("%02x", packet[i]);
    }
    printf("\n");
}
void come_on_packet(parse *ps)
{
    FILE *fp = fopen("/root/Desktop/drone/pls.mp4", "a+");
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
            //cout << "Packet is coming"<<endl;
            int packet_len = pkthdr->len;
            int len = packet_len;
            uint8_t* check_packet;
            struct radiotap_header *rp = (struct radiotap_header*)packet;
            packet+=rp->header_length;
            struct ieee80211_common *com = (struct ieee80211_common*)packet;
            if(com->frame_control_field==0x88){
                packet+=sizeof(ieee80211_common);
                if(com->more==1){
                    struct ieee80211_qos_frame *qos = (struct ieee80211_qos_frame*)packet;
                    if(memcmp(qos->src,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->bssid,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->sta, ps->using_controller_mac(),6)==0){
                        packet+=sizeof(ieee80211_qos_frame);
                        if(start==true){
                            memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                            offset += packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                        }
                        else{
                            check_packet=(uint8_t*)packet+8;
                            struct iphdr *iph = (struct iphdr*)(check_packet);
                            if(iph->protocol==0x11 && iph->daddr==0x020aa8c0 && iph->saddr==0x010aa8c0)
                            {
                                struct udphdr *udph = (struct udphdr*)(check_packet+iph->ihl*4);
                                if(udph->dest==ntohs(7797) && udph->source==ntohs(62512)){
                                    start=true;
                                    memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                    offset += packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                                }
                            }
                        }
                    }
                }
                else if(com->more==0){
                    struct ieee80211_qos_frame *qos = (struct ieee80211_qos_frame*)packet;
                    if(memcmp(qos->src,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->bssid,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->sta, ps->using_controller_mac(),6)==0){
                        if(start==true){
                            packet+=sizeof(ieee80211_qos_frame);
                            memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                            fwrite(video+38,1,1460,fp);// fucking 2bytes
                            showme(video,sizeof(video));
                            memset(video,0,sizeof(video));
                            offset = 0;
                            start=false;
                        }
                    }
                }
                else
                    continue;
            }
            else
                continue;
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
    fclose(fp);
}
