#include "parse.h"
#include "convert_char_to_binary.h"

using namespace std;

parse::parse(int argc, char*argv[]){
    this->interface=argv[1];
    check_argc(argc,argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=4){ //인자 갯수 판별, 인자의 수가 4개가 안 될 경우 사용법 출력 후 종료
        cout << "<usage> : <Interface> <Send DHCP SERVER IP> <Send DHCP SERVER MAC>" << endl;
        exit(1);
    }
    char_to_binary(argv[3],this->attacker_dhcp_mac);
    inet_pton(AF_INET, argv[2],&this->attacker_dhcp_ip);
    memset(this->broadcast,255,6);
    memset(this->allpacket,0,6);
    parse_data_in_linux();
}
void parse::get_my_mac(uint8_t mac[6]){
    memcpy(this->attacker_mac,mac,6);
}
void parse::get_my_ip(char ip[16]){
    inet_pton(AF_INET, ip, &this->attacker_ip);
}
void parse::parse_data_in_linux(){ //공격자, 즉 나의 mac주소 파씽
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

    //-----------------------------get my(attacker) ip!!----------------------------- // 공격자 즉 나의 ip 파씽
    FILE *i;
    i=popen("ip addr | grep 'inet' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'","r");
    char host_ip[16];
    fgets(host_ip,16,i);
    this->get_my_ip(host_ip);
}
void parse::parse_client_mac(uint8_t mac[6]){
    memcpy(this->client_mac,mac,6);
}
char *parse::using_interface(){
    return this->interface;
}
uint8_t *parse::using_allpacket(){
    return this->allpacket;
}
uint8_t *parse::using_broadcast(){
    return this->broadcast;
}
uint8_t *parse::using_attacker_dhcp_server_mac(){
    return this->attacker_dhcp_mac;
}
uint32_t *parse::using_attacker_dhcp_server_ip(){
    return &this->attacker_dhcp_ip;
}
void parse::get_dhcp_data_length(int length){
    this->dhcp_data_length=length;
}
void parse::get_dhcp_data(uint8_t *packet){
    memcpy(this->dhcp_data,packet,this->dhcp_data_length);
}
uint8_t * parse::using_dhcp_data(){
    return this->dhcp_data;
}
void parse::make_dhcp_arr_space(int size){
    this->dhcp_data = new uint8_t[size];
}
void parse::make_dhcp_length(int size){
    this->dhcp_length = size;
    this->dhcp_packet = new uint8_t[this->dhcp_length];
}
void parse::make_dhcp_packet(uint8_t *packet, int length, bool pointer){
    if(pointer == false)
        memcpy(this->dhcp_packet,packet,length);
    else if(pointer == true){
        memcpy(this->dhcp_packet+this->pre_packet_length,packet,length); //
    }
}
int parse::using_dhcp_data_length(){
    return this->dhcp_data_length;
}
int parse::using_dhcp_length(){
    return this->dhcp_length;
}
uint8_t *parse::using_dhcp_packet(){
    return this->dhcp_packet;
}
void parse::show_dhcp_packet(){ // 패킷 출력 함수
    for(int i=0; i<this->dhcp_length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",this->dhcp_packet[i]);
    }
    cout << endl;
}
void parse::make_arp_packet(){ //arp 사용안함
    struct using_arp_type_data utd;
    this->arp_length= sizeof(struct ether_header) + sizeof(struct arp_header);
    this->arp_packet = new uint8_t[this->arp_length];
    memcpy(this->arp_packet,this->origin_dhcp_mac,6); // ?? right?
    memcpy(this->arp_packet+6,this->attacker_mac,6); //?? right?
    memcpy(this->arp_packet+12,&utd.ether_arp_type,2);
    memcpy(this->arp_packet+14,&utd.hardware_type,2);
    memcpy(this->arp_packet+16,&utd.ipv4_type,2);
    memcpy(this->arp_packet+18,&utd.hardware_size,1);
    memcpy(this->arp_packet+19,&utd.protocol_size,1);
    memcpy(this->arp_packet+20,&utd.reply_opcode,2);
    memcpy(this->arp_packet+22,this->attacker_mac,6); // ?? right?
    memcpy(this->arp_packet+28,this->using_broadcast(),4); // ?? modi?255.255.255.255 or 0.0.0.0
    memcpy(this->arp_packet+32,this->origin_dhcp_mac,6); // ?? right?
    memcpy(this->arp_packet+38,&this->origin_dhcp_ip,4); // ?? right?
    /*
    cout << "<arp packet>\n";
    for(int i=0; i<this->arp_length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",this->arp_packet[i]);
    }
    */
}
uint8_t *parse::using_arp_packet(){ //사용안했음
    return this->arp_packet;
}
int parse::using_arp_packet_length(){ //사용안했음
    return this->arp_length;
}
void parse::parse_transaction_id(uint16_t id){
    this->transaction_id=id;
}
uint16_t *parse::using_transaction_id(){
    return &this->transaction_id;
}
