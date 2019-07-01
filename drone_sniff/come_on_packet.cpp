#include "ieee80211.h"
#include "come_on_packet.h"

//문제점 : 로직버그가 있다. 똑같은 패킷이 여러개 복사된다 그것만 해결하면 될듯

uint8_t video[4096];//파일에 저장할 분할패킷을 다합친 패킷
int offset=0; //저장된 분할 패킷만큼 건너뛰기 위한 offset
bool start = false; //포트와 이이피 맥을 검증하여서 일치하면 true

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
            int packet_len = pkthdr->len;
            uint8_t* check_packet;
            struct radiotap_header *rp = (struct radiotap_header*)packet;
            packet+=rp->header_length;
            struct ieee80211_common *com = (struct ieee80211_common*)packet;
            if(com->frame_control_field!=0x88)
                continue;
            if(com->frame_control_field==0x88){
                packet+=sizeof(ieee80211_common);
                //분할패킷이 있는지 검증
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
                            // 아이피와 포트를 확인하고 내가 인자로넘겨준 정보들과 일치하면 패킷뭉탱이 저장하고
                            // 그다음에 오는 패킷을 받기위해 start를 true로 바꿈
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
                // 분할패킷이 더이상 없으면
                else if(com->more==0){
                    struct ieee80211_qos_frame *qos = (struct ieee80211_qos_frame*)packet;
                    if(memcmp(qos->src,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->bssid,ps->using_drone_mac(),6)==0 &&
                            memcmp(qos->sta, ps->using_controller_mac(),6)==0){
                        //다합친 패킷 파일에 쓰기
                        if(start==true){
                            //이미 앞에서 검증되었으므로 패킷합침
                            packet+=sizeof(ieee80211_qos_frame);
                            memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                            fwrite(video+38,1,1458,fp);
                            showme(video+38,1458);
                            memset(video,0,sizeof(video));
                            offset = 0;
                            start=false;
                            //저장패킷 초기화 및 아이피 포트확인하는 start도 false로 초기화
                            //그리고 다시 처음부터 패킷을 합침으로 offset도 초기화
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
