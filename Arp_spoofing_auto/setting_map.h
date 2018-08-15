#ifndef SETTING_MAP_H
#define SETTING_MAP_H
#include <iostream>
#include <map>

using namespace std;

class keydata
{
 public:
    uint8_t mac[6];
    bool operator < (const keydata new_mac) const{
        return tie(mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]) < tie(new_mac.mac[0],new_mac.mac[1],new_mac.mac[2],new_mac.mac[3],new_mac.mac[4],new_mac.mac[5]);
    }
    keydata();
}__attribute__((packed));

struct valuedata
{
    int sequence;
    uint32_t ip;
};

#endif // SETTING_MAP_H
