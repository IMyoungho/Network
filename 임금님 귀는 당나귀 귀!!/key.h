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
    int sequence{0};
    uint8_t all_packet[1500];
    int save_length{0};

};
class setdata{
public:
    uint8_t send_packet[1500];
    bool operator<(const setdata setd) const{
        return tie(send_packet) < tie(setd.send_packet);
    }
}__attribute__((packed));
struct setvalue{
    int length;
};




#endif // KEY_H
