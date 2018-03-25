#ifndef GET_GATEWAY_DATA_H
#define GET_GATEWAY_DATA_H
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ether.h>
#include "parse_data.h"
#include "send_packet.h"
#include "make_request_packet.h"

using namespace std;

void get_gateway_data(parse_data *parse) //fix here
{
    //***************************Make ARP gateway request Packet*****************************
    uint8_t ask_gateway_packet[42]{0};
    make_request_packet(parse,ask_gateway_packet,*parse->using_gateway_ip());
    parse->get_gateway_mac(send_receive_packet(parse,ask_gateway_packet,42));
}
#endif // GET_GATEWAY_DATA_H
