#include "parse.h"

using namespace std;

parse::parse(int argc, char*argv[]){
    this->interface=argv[1];
    check_argc(argc);
}
void parse::check_argc(int argc){
    if(argc!=2){
        cout << "<usage> : <Interface>" << endl;
        exit(1);
    }
}
char* parse::using_interface(){
    return this->interface;
}
void parse::get_my_mac(uint8_t mac[6]){
    memcpy(this->my_mac,mac,6);
}
void parse::get_my_ip(char ip[16]){
    inet_pton(AF_INET, ip, &this->my_ip);
}
uint8_t *parse::using_my_mac(){
    return this->my_mac;
}
uint32_t parse::using_my_ip(){
    return this->my_ip;
}
void parse::parse_data_in_linux()
{
    //-----------------------------get my(attacker) mac!!-----------------------------
    char host_mac[18];//mymac
    FILE *m;
    string str_ifconfig = "ifconfig ";
    string interface = this->using_interface();
    string regex = " | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'";
    str_ifconfig=str_ifconfig+interface+regex;

    const char *command=str_ifconfig.c_str();
    m=popen(command,"r");
    fgets((char*)host_mac,18, m);
    uint8_t mac[6];
    char_to_binary(host_mac,mac);
    this->get_my_mac(mac);

    //-----------------------------get my(attacker) ip!!-----------------------------
    FILE *i;
    i=popen("ip addr | grep 'inet' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'","r");
    char host_ip[15];
    fgets(host_ip,15,i);
    this->get_my_ip(host_ip);
}
void parse::get_send_packet_length(int length){
    this->send_packet_length=length;
    this->send_packet = new uint8_t [length];
}
int parse::using_send_packet_length(){
    return this->send_packet_length;
}
void parse::make_send_packet(struct iphdr *ipd,uint8_t *data){
    memcpy(this->send_packet,ipd,ipd->ihl*4);
    memcpy(this->send_packet+ipd->ihl*4,data,this->send_packet_length-ipd->ihl*4);
    for(int i=0; i<this->send_packet_length; i++)
    {
        if(i%16==0)
            cout << endl;
        printf("%02x ",this->send_packet[i]);
    }
}
uint8_t *parse::using_send_packet()
{
    return this->send_packet;
}
