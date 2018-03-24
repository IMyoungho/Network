#include "cal_checksum.h"

#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2

cal_checksum::cal_checksum(){ }
void cal_checksum::get_iphdr(struct iphdr *ip){
    ip->check=0;
    this->iph=ip;
}
void cal_checksum::get_udphdr(struct udphdr *up){
    up->check=0;
    this->udph=up;
}
void cal_checksum::get_tcphdr(struct tcphdr *tp){
    tp->check=0;
    this->tcph=tp;
}
int cal_checksum::calculation(uint8_t *temp, int length, bool change){
    int checksum{0};

    for(int i=0; i<length; i+=2)
    {
        if(i==length-1 && change == true)
        {
            int last_arr=temp[length-1] << 8;
            checksum+=last_arr;
            break;
        }
        checksum += (temp[i] << 8) + temp[i+1];
    }
    int carry{0};
    while(checksum>=65536)
    {
        checksum-=65536;
        carry++;
    }
    checksum+=carry;
    return ~checksum;
}
uint16_t cal_checksum::checksum(int select_checksum){
    uint8_t *temp;
    uint16_t checksum;
    int length{0};
    switch (select_checksum) {
        case ipchecksum:
        {
            length = this->iph->ihl*4;
            temp=new uint8_t[length];
            memcpy(temp,(uint8_t*)this->iph,length);
            checksum = calculation(temp,length,false);
            delete []temp;
        }
        break;
        case udpchecksum:
        {

        }
        break;
        case tcpchecksum:
        {

        }
        break;
        default:
            break;
    }
    return checksum;
}
