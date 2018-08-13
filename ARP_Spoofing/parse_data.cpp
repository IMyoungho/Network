#include <iostream>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "parse_data.h"


using namespace std;

parse_data::parse_data(int argc, char *argv[]){
    this->interface=argv[1];
    check_argc(argc,argv);
}
void parse_data::check_argc(int argc, char *argv[]){
    if(argc!=4){
        cout << " >> Syntax Error !!" << endl;
        cout << " >> < Usage > : < interface > < target ip > <victim ip> " << endl;
        exit(1);
    }
    inet_pton(AF_INET, argv[2],&this->target_ip);
    inet_pton(AF_INET, argv[3],&this->sender_ip);
}
char* parse_data::using_interface(){
    return this->interface;
}
void parse_data::get_attacker_mac(uint8_t mac[6]){
    memcpy(this->attack_mac,mac,6);
}
void parse_data::get_attacker_ip(char ip[16]){
    inet_pton(AF_INET, ip, &this->attack_ip);
}
void parse_data::get_target_mac(uint8_t mac[6]){
    memcpy(this->target_mac,mac,6);
}
void parse_data::get_sender_mac(uint8_t mac[6]){
    memcpy(this->sender_mac,mac,6);
}
uint8_t* parse_data::using_attack_mac(){
    return this->attack_mac;
}
uint32_t *parse_data::using_attack_ip(){
    return &this->attack_ip;
}
uint8_t* parse_data::using_sender_mac(){
    return this->sender_mac;
}
uint32_t *parse_data::using_sender_ip(){
    return &this->sender_ip;
}
uint8_t* parse_data::using_target_mac(){
    return this->target_mac;
}
uint32_t *parse_data::using_target_ip(){
    return &this->target_ip;
}
void parse_data::get_arp_reply_packet_data(uint8_t packet[42], int packet_len, pcap_t *pcaphandle){
    memcpy(this->send_arp_reply_packet,packet,static_cast<size_t>(packet_len));
    this->used_pcap_t=pcaphandle;
    this->send_arp_length=packet_len;
}
uint8_t *parse_data::using_send_arp_reply_packet(){
    return this->send_arp_reply_packet;
}
int parse_data::using_send_arp_reply_length(){
    return this->send_arp_length;
}
pcap_t *parse_data::using_send_arp_reply_pcaphandle(){
    return this->used_pcap_t;
}
