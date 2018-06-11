#include "parse.h"

parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=4)
    {
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "    >> 사용법 : <dev>\n";
        exit(1);
    }
    this->interface=argv[1];
    inet_pton(AF_INET,argv[2],&this->drone_ip);
    inet_pton(AF_INET,argv[3],&this->device_ip);
    //come_on_packet(); //temp
}
char *parse::using_interface(){
    return this->interface;
}
void parse::come_on_packet()
{
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const u_int8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(this->interface,BUFSIZ,1,1,errbuf);
    while(true)
    {
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (ret)
        {
            case 1:
            {
                cout << "Packet is coming"<< endl;
                int packet_len = pkthdr->len;
                struct ether_header *ep= (struct ether_header*)packet;
                if(ep->ether_type==ntohs(ETHERTYPE_IP))
                {
                    cout << "IP packet is comming" << endl;
                    struct iphdr *iph = (struct iphdr*)(packet+sizeof(ether_header));
                    if(iph->protocol==0x11){
                        if(iph->saddr==this->device_ip && iph->daddr==this->drone_ip){
                            cout << ">> UDP packet is comming" << endl;
                            struct udphdr *udph = (struct udphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                            uint8_t aa[55]{0};
                            memcpy(aa,ep,sizeof(struct ether_header));
                            memcpy(aa+sizeof(ether_header),iph,iph->ihl*4);
                            memcpy(aa+sizeof(ether_header)+iph->ihl*4,udph,ntohs(udph->len));
                            for(int i=0; i<packet_len; i++)
                            {
                                if(i%16==0)
                                    cout <<endl;
                                printf("%02x ",aa[i]);
                            }
                            pcap_sendpacket(pcd,(const u_char*)aa,sizeof(aa));
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
                pcd = pcap_open_live(this->interface, BUFSIZ, 1 , 1, errbuf);
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
}
