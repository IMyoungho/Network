#include "get_sender_data.h"

void get_sender_data(parse_data *parse){ //fix here
    //***************************Make ARP target request Packet*****************************
    uint8_t ask_sender_packet[42]{0};
    make_request_packet(parse,ask_sender_packet,*parse->using_sender_ip());
    parse->get_sender_mac(send_receive_packet(parse,ask_sender_packet,42));
}
