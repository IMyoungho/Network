#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

using namespace std;

class parse {
private:
    char *interface;
    uint8_t attacker_dhcp_mac[6];
    uint32_t attacker_dhcp_ip;
    uint8_t  client_mac[6];
    uint8_t *dhcp_data;
    int dhcp_data_length;
    uint8_t *dhcp_packet;
    int dhcp_length;
    uint16_t transaction_id;

public:
    int pre_packet_length;
    uint8_t broadcast[6];
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char* using_interface();
    uint8_t *using_broadcast();
    uint8_t *using_attacker_dhcp_server_mac();
    uint32_t *using_attacker_dhcp_server_ip();
    uint8_t *using_normal_dhcp_mac();
    uint32_t *using_normal_dhcp_ip();
    uint8_t *using_client_mac();
    uint32_t *using_client_ip();

    void parse_normal_dhcp_mac(uint8_t mac[6]);
    void parse_normal_dhcp_ip(uint32_t ip);
    void parse_client_mac(uint8_t mac[6]);
    void parse_client_ip(uint32_t ip);
    void make_dhcp_arr_space(int size);
    void get_dhcp_data_length(int length);
    void get_dhcp_data(uint8_t *packet);
    void make_dhcp_length(int size);
    void make_dhcp_packet(uint8_t *packet, int length, bool pointer);
    uint8_t *using_dhcp_data();
    int using_dhcp_data_length();
    uint8_t *using_dhcp_packet();
    int using_dhcp_length();
    void show_dhcp_packet();
    void parse_transaction_id(uint16_t id);
    uint16_t *using_transaction_id();
};

#endif // PARSE_H
