#ifndef KEY_H
#define KEY_H
#include <iostream>
#include <map>

using namespace std;

class keydata
{
 public:
    uint8_t bssid[6];
    bool operator < (const keydata new_bssid) const{
        return tie(bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]) < tie(new_bssid.bssid[0],new_bssid.bssid[1],new_bssid.bssid[2],new_bssid.bssid[3],new_bssid.bssid[4],new_bssid.bssid[5]);
    }
    keydata();
}__attribute__((packed));

struct valuedata
{
    uint8_t essid[32]{0};
    int channel;
    uint8_t memo[30]{0};
    int sequence{0};
};

#endif // KEY_H
