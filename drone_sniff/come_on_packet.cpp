#include "ieee80211.h"
#include "come_on_packet.h"

//문제점 : 로직버그가 있다. 똑같은 패킷이 여러개 복사된다 그것만 해결하면 될듯
//로직은 해결한거 같은 마지막 패킷이 짤려나왓음
//video_pcap => number 94 udp packet 패킷이 짤려나왓음 -> 그 이후도 더이상 저장이 안되어잇음 -> 이전패킷과 동일할 경우 무시해야함

//uint8_t video[10000];//파일에 저장할 분할패킷을 다합친 패킷
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
//    int client_socket;
//    struct sockaddr_in   server_addr;
//    char buff[1458];
//    client_socket  = socket( PF_INET, SOCK_STREAM, 0);
//    if( -1 == client_socket)
//    {
//        printf( "socket 생성 실패\n");
//        exit( 1);
//    }
//    memset( &server_addr, 0, sizeof( server_addr));
//    server_addr.sin_family     = AF_INET;
//    server_addr.sin_port       = htons(7979);
//    server_addr.sin_addr.s_addr= inet_addr( "127.0.0.1");

//    if( -1 == connect( client_socket, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
//    {
//        printf( "접속 실패\n");
//        exit( 1);
//    }     // +1: NULL까지 포함해서 전송


//  ========================================================================================================================
    FILE *fp = fopen("/root/Desktop/drone/pls.mp4", "w"); // file
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const u_int8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    uint8_t video[10000];                                // 1460개로 안됬던 이유 -> 1460개가 넘는경우가 발생했다.
    int write_length=0;
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
                                printf("second offset = %d\n",offset);
                                memcpy(video+offset,packet,(size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                offset += (size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                                write_length+=offset;
                                printf("third offset = %d\n",offset);
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
                                        printf("init offset = %d\n",offset);
                                        memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                        offset += (size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                                        write_length+=offset;
                                        printf("fisrt offset = %d\n",offset);
                                    }
                                }
                            }
                        }
                    }
                    // 분할패킷이 더이상 없으면
                    else if(com->more==0){
                        //앞에서 진행한 검증확인 true
                        if(start!=true)
                            continue;
                        struct ieee80211_qos_frame *qos = (struct ieee80211_qos_frame*)packet;
                        if(memcmp(qos->src,ps->using_drone_mac(),6)==0 &&
                                memcmp(qos->bssid,ps->using_drone_mac(),6)==0 &&
                                memcmp(qos->sta, ps->using_controller_mac(),6)==0){
                            //다합친 패킷 파일에 쓰기
                                packet+=sizeof(ieee80211_qos_frame);
                                if(write_length<1458)
                                    write_length+=(size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame)-38;//38 means header length
                                else if(write_length>=1458 && write_length <=1560)
                                    write_length-=102;

                                printf("last offset = %d\n",offset);
                                printf("write_length = %d",write_length);
                                memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                //uint8_t box[write_length]; //origin
                                uint8_t *box = new uint8_t[write_length];//origin or delete
                                memcpy(box,video+38,(size_t)write_length);
                                fwrite(box,1,(size_t)write_length,fp);   //file -> size fix!! this is error logic
                                showme(box,write_length);                //file
                                //저장패킷 초기화 및 아이피 포트확인하는 start도 false로 초기화
                                //그리고 다시 처음부터 패킷을 합침으로 offset도 초기화
                                memset(video,0,1496);
                                offset = 0;
                                start=false;
                                write_length=0;
                                delete [] box; //origin or delete
//                                memcpy(buff,video+38,1458);                      //client
//                                showme((uint8_t*)buff,sizeof(buff));             //client
//                                send(client_socket,(char*)buff, strlen(buff),0); //client
//                                memset(video,0,sizeof(video));                   //client
//                                memset(buff,0,sizeof(buff));                     //client
                        }
                    }
    //                else
    //                    continue; //logic bug1
                }
    //            else
    //                continue; //logic bug2
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
//    close( client_socket); //client
    fclose(fp);//file
}
