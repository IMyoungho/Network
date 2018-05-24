#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <map>
#include <atomic>
#include "ieee80211.h"
#include "key.h"
#include "convert_type.h"
#include "keyboard_event.h"
#define BEACON 0x80

using namespace std;

class parse {
private:
    char *interface;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc);
    char *using_interface();
    void show_me(int range, uint8_t *data);
    uint8_t *check_tag(uint8_t *data, int &datalen, uint8_t &taglen, bool &get_check);
    uint8_t *check_tag(uint8_t *data, int &datalen, uint8_t &taglen);
    void scanning(map<keydata, valuedata> &map_beacon, atomic<bool> &run);
    void show_ap(map<keydata, valuedata> &map_beacon);
};
#endif // PARSE_H
