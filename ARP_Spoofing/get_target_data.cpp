#include "get_target_data.h"

void get_target_data(parse_data *parse){
    //***************************Make ARP gateway request Packet*****************************
    uint8_t ask_target_packet[42]{0};
    make_request_packet(parse,ask_target_packet,*parse->using_target_ip());
    parse->get_target_mac(send_receive_packet(parse,ask_target_packet,42));
}
