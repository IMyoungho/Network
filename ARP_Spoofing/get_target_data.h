#ifndef GET_TARGET_DATA_H
#define GET_TARGET_DATA_H

#include "make_request_packet.h"
#include "send_packet.h"
void get_target_data(parse_data *parse) //fix here
{
    //***************************Make ARP target request Packet*****************************
    uint8_t ask_target_packet[42]{0};
    make_request_packet(parse,ask_target_packet,*parse->using_target_ip());
    parse->get_target_mac(send_receive_packet(parse,ask_target_packet,42));
}
#endif // GET_TARGET_DATA_H
