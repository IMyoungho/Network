#include "parse.h"

parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!= 5){
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "    >> 사용법 : <dev>\n";
        exit(1);
    }
    this->interface=argv[1];
    inet_pton(AF_INET,argv[2],&this->drone_ip);
    char_to_binary(argv[3],this->drone_mac);
    inet_pton(AF_INET,argv[4],&this->myip);
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
    ip->saddr=this->myip;
    ip->daddr=this->drone_ip;
    ip->tos=0x00;
    ip->ttl=0x80;
    ip->id=ntohs(0x1120);

    struct udphdr *up = new udphdr;
    up->dest=ntohs(0x22b9);
    up->source=ntohs(0xf405);
    for(int i=11; i<17;i++)
        make_excute(ep,ip,up,cc,i);
    make_command(ep,ip,up,cc);
    make_take_off(ep,ip,up,cc);
    make_landing(ep,ip,up,cc);
    make_up(ep,ip,up,cc);
    make_down(ep,ip,up,cc);
    make_go(ep,ip,up,cc);
    make_back(ep,ip,up,cc);
    make_left(ep,ip,up,cc);
    make_right(ep,ip,up,cc);
    delete ep; delete ip; delete up;
}
void parse::make_excute(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc, int type){
    switch (type) {
        case upexcute:
        case rightexcute:
        {
            ip->tot_len=ntohs(0x0028);
            cc->get_iphdr(ip);
            ip->check=ntohs(cc->checksum(ipchecksum));
            up->len=ntohs(0x0014);
            cc->get_udphdr(up);
            cc->get_pesudo(udpchecksum);
        }
        break;
        case backexcute:
        case downexcute:
        case leftexcute:
        {
            ip->tot_len=ntohs(0x0029);
            cc->get_iphdr(ip);
            ip->check=ntohs(cc->checksum(ipchecksum));
            up->len=ntohs(0x0015);
            cc->get_udphdr(up);
            cc->get_pesudo(udpchecksum);
        }
        break;
        case goexcute:
        {
            ip->tot_len=ntohs(0x0026);
            cc->get_iphdr(ip);
            ip->check=ntohs(cc->checksum(ipchecksum));
            up->len=ntohs(0x0012);
            cc->get_udphdr(up);
            cc->get_pesudo(udpchecksum);
        }
        break;
        default:
        break;

    }
    switch (type) {
        case upexcute:
        {
            uint8_t data[12]={0x67,0x6f,0x30,0x20,0x30,0x20,0x33,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->up_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->up_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->up_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->up_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
        }
        break;
        case downexcute:
        {
            uint8_t data[13]={0x67,0x6f,0x20,0x30,0x20,0x30,0x20,0x2d,0x33,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->down_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->down_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->down_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->down_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
        }
        break;
        case goexcute:
        {
            uint8_t data[12]={0x67,0x6f,0x20,0x30,0x20,0x33,0x30,0x20,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->go_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->go_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->go_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->go_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
            for(int i=0; i<54; i++)
            {
                if(i%16==0)
                    cout << endl;
                printf("%02x ",this->go_excute[i]);
            }

        }
        break;
        case backexcute:
        {
            uint8_t data[13]={0x67,0x6f,0x20,0x30,0x20,0x2d,0x33,0x30,0x20,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->back_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->back_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->back_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->back_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
        }
        break;
        case leftexcute:
        {
            uint8_t data[13]={0x67,0x6f,0x20,0x2d,0x33,0x30,0x20,0x30,0x20,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->left_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->left_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->left_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->left_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
        }
        break;
        case rightexcute:
        {
            uint8_t data[12]={0x67,0x6f,0x20,0x33,0x30,0x20,0x30,0x20,0x30,0x20,0x32,0x35};
            up->check=ntohs(cc->checksum(udpchecksum,data));
            memcpy(this->right_excute,(uint8_t*)ep,sizeof(ether_header));
            memcpy(this->right_excute+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
            memcpy(this->right_excute+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
            memcpy(this->right_excute+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
        }
        break;
        default:
        break;
    }
}
void parse::make_command(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0023);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000f);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[7]={0x63,0x6f,0x6d,0x6d,0x61,0x6e,0x64};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->command,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->command+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->command+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->command+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
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
    memcpy(this->takeoff+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_landing(struct ether_header*ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0020);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000c);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[4]={0x6c,0x61,0x6e,0x64};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->landing,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->landing+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->landing+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->landing+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_up(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0021);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000d);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[5]={0x75,0x70,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->up,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->up+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->up+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->up+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));

}
void parse::make_down(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0023);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000f);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[7]={0x64,0x6f,0x77,0x6e,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->down,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->down+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->down+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->down+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_go(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0026);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x0012);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[10]={0x66,0x6f,0x72,0x77,0x61,0x72,0x64,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->go,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->go+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->go+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->go+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_back(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0023);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000f);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[7]={0x62,0x61,0x63,0x6b,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->back,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->back+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->back+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->back+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_left(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0023);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x000f);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[7]={0x6c,0x65,0x66,0x74,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->left,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->left+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->left+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->left+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
void parse::make_right(struct ether_header *ep, struct iphdr *ip, struct udphdr*up, cal_checksum *cc){
    ip->tot_len=ntohs(0x0024);
    cc->get_iphdr(ip);
    ip->check=ntohs(cc->checksum(ipchecksum));
    up->len=ntohs(0x0010);
    cc->get_udphdr(up);
    cc->get_pesudo(udpchecksum);
    uint8_t data[8]={0x72,0x69,0x67,0x68,0x74,0x20,0x33,0x30};
    up->check=ntohs(cc->checksum(udpchecksum,data));

    memcpy(this->right,(uint8_t*)ep,sizeof(ether_header));
    memcpy(this->right+sizeof(ether_header),(uint8_t*)ip,ip->ihl*4);
    memcpy(this->right+sizeof(ether_header)+ip->ihl*4,(uint8_t*)up,sizeof(udphdr));
    memcpy(this->right+sizeof(ether_header)+ip->ihl*4+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
}
