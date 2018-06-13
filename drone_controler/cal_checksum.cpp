#include "cal_checksum.h"

#define ipchecksum 0
#define udpchecksum 1
#define tcpchecksum 2
#define icmpchecksum 3
#define OUT_OF_RANGE 65536

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
void cal_checksum::get_icmphdr(struct icmphdr *icp){
    icp->check=0;
    this->icph=icp;
}
void cal_checksum::get_pesudo(int type){
    this->pseu.src_ip = this->iph->saddr;
    this->pseu.dst_ip = this->iph->daddr;
    this->pseu.reserved = 0;
    this->pseu.protocol = this->iph->protocol;

    switch (type) {
        case udpchecksum:
            this->pseu.length = this->udph->len;
        break;
        case tcpchecksum:
            this->pseu.length = htons(ntohs(this->iph->tot_len)-this->iph->ihl*4);
        break;
        default:
            break;
    }
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
    int carry_count{0};
    while(checksum>=OUT_OF_RANGE)
    {
        checksum-=OUT_OF_RANGE;
        carry_count++;
    }
    checksum+=carry_count;
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
            temp = new uint8_t[length];
            memcpy(temp,(uint8_t*)this->iph,length);
            checksum = calculation(temp,length,false);
            delete []temp;
        }
        break;
        default:
            break;
    }
    return checksum;
}
uint16_t cal_checksum::checksum(int select_checksum, uint8_t *data){
    uint8_t *temp;
    uint16_t checksum;
    int length{0};
    switch (select_checksum) {
        case udpchecksum:
        {
            length = ntohs(this->udph->len) + sizeof(struct pesudo);
            temp = new uint8_t[length];
            memcpy(temp,(uint8_t*)&this->pseu,sizeof(struct pesudo));
            memcpy(temp+sizeof(struct pesudo),(uint8_t*)this->udph, sizeof(struct udphdr));
            memcpy(temp+sizeof(struct pesudo)+sizeof(udphdr),data,sizeof(data)/sizeof(uint8_t));
            checksum = calculation(temp,length,true);

        }
        break;
        default:
            break;
    }
    return checksum;
}

