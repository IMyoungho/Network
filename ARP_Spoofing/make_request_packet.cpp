#include "make_request_packet.h"

void make_request_packet(parse_data *parse, uint8_t make_packet[42], uint32_t ask_ip){
    memset(make_packet,0,42);
    memset(make_packet,0xFF,6);
    memcpy(make_packet+6,parse->using_attack_mac(),6);
    memcpy(make_packet+12,&parse->uat.ether_arp_type,2);
    memcpy(make_packet+14,&parse->uat.hardware_type,2);
    memcpy(make_packet+16,&parse->uat.ipv4_type,2);
    memcpy(make_packet+18,&parse->uat.hardware_size,1);
    memcpy(make_packet+19,&parse->uat.protocol_size,1);
    memcpy(make_packet+20,&parse->uat.request_opcode,2);
    memcpy(make_packet+22,parse->using_attack_mac(),6);
    memcpy(make_packet+28,parse->using_attack_ip(),4);
    memset(make_packet+32,0xFF,6);
    memcpy(make_packet+38,&ask_ip,4);
}
