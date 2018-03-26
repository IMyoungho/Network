#include "parse.h"
#include "conver_char_to_binary.h"

using namespace std;

parse::parse(int argc, char*argv[]){
    this->interface=argv[1];
    check_argc(argc,argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=4){
        cout << "<usage> : <Interface> <Send DHCP SERVER IP> <Send DHCP SERVER MAC>" << endl;
        exit(1);
    }
    char_to_binary(argv[3],this->attacker_dhcp_mac);
    inet_pton(AF_INET, argv[2],&this->attacker_dhcp_ip);
    memset(this->broadcast,255,6);
}

void parse::parse_client_mac(uint8_t mac[6]){
    memcpy(this->client_mac,mac,6);
}
char *parse::using_interface(){
    return this->interface;
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
void parse::show_dhcp_packet(){
    for(int i=0; i<this->dhcp_length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",this->dhcp_packet[i]);
    }
    cout << endl;
}
void parse::parse_transaction_id(uint16_t id){
    this->transaction_id=id;
}
uint16_t *parse::using_transaction_id(){
    return &this->transaction_id;
}
