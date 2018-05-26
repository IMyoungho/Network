#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <map>
#include <atomic>
#include <thread>
#include "hopping_channel.h"
#include "ieee80211.h"
#include "key.h"
#include "convert_type.h"
#include "keyboard_event.h"
#define BEACON 0x80

using namespace std;

class parse {
private:
    char *interface;
    int ap_count;
    int *ap_num;
    int create_ap_count;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc);
    char *using_interface();
    void show_me(int range, uint8_t *data);
    uint8_t *check_tag(uint8_t *data, int &datalen, uint8_t &taglen, bool &get_check);
    uint8_t *check_tag(uint8_t *data, int &datalen, uint8_t &taglen);
    void scanning(map<keydata, valuedata> &map_beacon, atomic<bool> &run);
    void show_ap(map<keydata, valuedata> &map_beacon);
    void ask_ap();
    void select_ap(map<keydata, valuedata> &map_beacon);
    void make_packet(uint8_t *packet, int packet_length, int count, map<setdata,setvalue> &set_packet);
};
#endif // PARSE_H
