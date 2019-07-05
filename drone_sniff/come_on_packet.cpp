#include "ieee80211.h"
#include "come_on_packet.h"

//할 일 :
// 1. 패킷이 마지막에 잘림 자꾸 몇 덩어리가 write 되지 않았음..
// 2. 무선랜이 느려지는 현상 -> 로직상 문제인가 아니면 인터페이스 문제인가.. ->> thread!!
// 3. 서버로 전송하기로 만들자. 0x00들이 발견되었음.. please.mp4 !!! 07.03. 새벽 04:01
// 4. 그게안되면 틴즈사용 or ARP 스푸핑

//해 결 :
// 1. video_pcap => number 94 udp packet 패킷이 짤려나왓음 -> 그 이후도 더이상 저장이 안되어잇음 -> 이전패킷과 동일할 경우 무시해야함
// 2. 똑같은 패킷이 여러개 복사된다 그것만 해결하면 될듯 -> 인터페이스 문제같음
// 3. Sequence number와 fragment number를 비교해줘서 중복값 문제를 해결함

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
    int client_socket;
    struct sockaddr_in   server_addr;
    client_socket  = socket( PF_INET, SOCK_STREAM, 0);
    if( -1 == client_socket)
    {
        printf( "socket 생성 실패\n");
        exit( 1);
    }
    memset( &server_addr, 0, sizeof( server_addr));
    server_addr.sin_family     = AF_INET;
    server_addr.sin_port       = htons(7979);
    server_addr.sin_addr.s_addr= inet_addr( "127.0.0.1");

    if( -1 == connect( client_socket, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
    {
        printf( "접속 실패\n");
        exit( 1);
    }     // +1: NULL까지 포함해서 전송


//  ========================================================================================================================
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const u_int8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    uint8_t video[10000];// 1460개로 안됬던 이유 -> 1460개가 넘는경우가 발생했다.
    int write_length=0;  // 패킷의 길이 측정 -> 보통 1460개의 길이지만 assemble 했을 때 길이가 각기다름 -> Ip header total length로 측정하기로함
    uint8_t frag=0;
    uint16_t seq=0;


    while(true)
    {
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (ret)
        {
            case 1:
            {
                int packet_len = pkthdr->len;
                uint8_t* check_packet; //제일 처음오는 fragment 패킷의 data+8부터 reassembled 패킷의 ip header이므로 이를 이용해 미리 ip와 port를 검사하기 위한 포인터

                struct radiotap_header *rp = (struct radiotap_header*)packet;
                packet+=rp->header_length;
                struct ieee80211_common *com = (struct ieee80211_common*)packet;
                //재전송 플래그 체크 -> 재전송 플래그가 없이도 재전송되는 패킷이 존재했다 -> 중복되지 않아도 재전송패킷이 있음..
//                if(com->frame_control_field!=0x88)
//                    continue;
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
                                if(qos->fragment_num > frag && qos->sequence_num ==seq){
                                    memcpy(video+offset,packet,(size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                    offset += (size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                                    frag=qos->fragment_num;
                                }
                            }
                            else{
                                // 아이피와 포트를 확인해서 필요한 데이터인지 분류함. 일치하면 패킷 데이터를 저장하고
                                // 그 다음에 오는 패킷을 받기위해 start를 true로 바꿈
                                check_packet=(uint8_t*)packet+8;
                                struct iphdr *iph = (struct iphdr*)(check_packet);
                                if(iph->protocol==0x11 && iph->daddr==0x020aa8c0 && iph->saddr==0x010aa8c0)
                                {
                                    struct udphdr *udph = (struct udphdr*)(check_packet+iph->ihl*4);
                                    if(udph->dest==ntohs(7797) && udph->source==ntohs(62512)){
                                        start=true;
                                        memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));
                                        offset += (size_t)packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame);
                                        write_length=ntohs(iph->tot_len)-28; //패킷의 총길이 저장
                                        frag=qos->fragment_num;
                                        seq=qos->sequence_num;
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
                        if(qos->fragment_num > frag && qos->sequence_num == seq){
                            if(memcmp(qos->src,ps->using_drone_mac(),6)==0 &&
                                    memcmp(qos->bssid,ps->using_drone_mac(),6)==0 &&
                                    memcmp(qos->sta, ps->using_controller_mac(),6)==0){
                                //다합친 패킷 파일에 쓰기
                                    packet+=sizeof(ieee80211_qos_frame);
                                    printf("write_length = %d",write_length);
                                    memcpy(video+offset,packet,packet_len-rp->header_length-sizeof(ieee80211_common)-sizeof(ieee80211_qos_frame));

                                    send(client_socket,(char*)video+38, (size_t)write_length-2,0); //client
                                    cout <<"\n >> video packet collecting" << endl;
                                    showme(video+38,write_length-2);                //file
                                    //저장패킷 초기화 및 아이피 포트확인하는 start도 false로 초기화
                                    //그리고 다시 처음부터 패킷을 합침으로 offset도 초기화
                                    memset(video,0,sizeof(video));
                                    offset = 0;
                                    start=false;
                                    write_length=0;
                                    seq=0;
                                    frag=0;
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
    close(client_socket); //client
}
