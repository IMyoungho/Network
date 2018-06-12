#include "parse.h"

parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!= 4){
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "    >> 사용법 : <dev>\n";
        exit(1);
    }
    this->interface=argv[1];
    inet_pton(AF_INET,argv[2],&this->drone_ip);
    char_to_binary(argv[3],this->drone_mac);
    //come_on_packet(); //temp
}
char *parse::using_interface(){
    return this->interface;
}

void parse::make_common_packet(cal_checksum *cc){
    struct ether_header *ep=new ether_header;
    memcpy(ep->ether_dhost,this->drone_mac,6);
    memset(ep->ether_shost,255,6);
    ep->ether_type=ntohs(0x800);

    struct iphdr *ip = new iphdr;
    ip->version=4;
    ip->ihl=5;
    ip->protocol=0x11;
    ip->frag_off=0x00;
    ip->saddr=ntohl(0xc0a80002);
    ip->daddr=this->drone_ip;
    ip->tos=0x00;
    ip->ttl=0x80;//
    ip->id=ntohs(0x1120);

    struct udphdr *up = new udphdr;
    up->dest=ntohs(0x22b9);
    up->source=ntohs(0xf405);
    make_excute(ep,ip,up,cc);
    make_take_off(ep,ip,up,cc);
    make_landing(ep,ip,up,cc);
    make_up(ep,ip,up,cc);
    make_down(ep,ip,up,cc);
    make_go(ep,ip,up,cc);
    make_back(ep,ip,up,cc);
    make_left(ep,ip,up,cc);
    make_right(ep,ip,up,cc);
}
void parse::make_excute(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_take_off(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0023);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000f);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[7]={0x74,0x61,0x6b,0x65,0x6f,0x66,0x66};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->takeoff,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->takeoff+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->takeoff+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->takeoff+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data));
    for(int i=0; i<49; i++)
    {
        if(i%16==0)
            cout << endl;
        printf("%02x ",this->takeoff[i]);
    }
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(this->interface, BUFSIZ, 1, 1, errbuf);
    pcap_sendpacket(pcd,this->takeoff,49);
}
void parse::make_landing(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_up(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_down(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_go(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_back(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_left(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
void parse::make_right(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){

}
