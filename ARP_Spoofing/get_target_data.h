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

void get_target_data(parse_data *parse); //fix here
#endif // GET_GATEWAY_DATA_H
