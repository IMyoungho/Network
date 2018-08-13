#ifndef MAKE_REQUEST_PACKET_H
#define MAKE_REQUEST_PACKET_H
#include <string.h>
#include "parse_data.h"

void make_request_packet(parse_data *parse, uint8_t make_packet[42], uint32_t ask_ip);
#endif // MAKE_REQUEST_PACKET_H
