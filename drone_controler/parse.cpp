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
    char_to_binary(argv[3],this->using_drone_mac());
    //come_on_packet(); //temp
}
char *parse::using_interface(){
    return this->interface;
}
uint32_t parse::using_drone_ip(){
    return this->drone_ip;
}
uint8_t *parse::using_drone_mac(){
    return this->drone_mac;
}
void parse::make_packet(){
    struct ether_header ep;
    uint8_t fake_mac[6];
    uint32_t fake_ip=0xc0a80a02;
    memset(fake_mac,255,6);
    memcpy(ep.ether_dhost,this->using_drone_mac(),6);
    memcpy(ep.ether_shost,fake_mac,6);
    ep.ether_type=ntohs(0x0800);
    struct iphdr iph;
    iph.version=4;
    iph.ihl=5;
    iph.tot_len=ntohs(0x0035);
    iph.frag_off=0x00;
    iph.ttl=0xff;
    iph.protocol=0x11;
    iph.daddr=this->drone_ip;
    iph.saddr=fake_ip;
}
