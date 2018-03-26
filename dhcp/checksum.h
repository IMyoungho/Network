#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include "parse.h"

#pragma pack(push,1)
struct pesudo{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t length;
};
#pragma pack(pop)

uint16_t cal_checksum(int length, uint8_t *packet, bool check)
{
    //패킷이 홀수일때
    int sum{0};
    for(int i=0; i<length; i+=2)
    {
        if(i==length-1 && check == true)
        {
            int last_arr=packet[length-1] << 8;
            sum+=last_arr;
            break;
        }
        int foward_arr=packet[i] << 8;
        sum+=foward_arr+packet[i+1];
    }
    int carry=0;
    while(sum>=65536)
    {
        sum-=65536;
        carry++;
    }
    sum+=carry;
    return ~sum;
}
uint16_t ip_checksum(struct iphdr *ip) //ip checksum 구할때 identification값 때문에 checksum 값이 바뀌는데 discover랑 비교해보기
{
    uint16_t checksum{0};
    ip->check=0;
    uint8_t temp[ip->ihl*4]{0};
    memcpy(temp,(uint8_t*)ip,ip->ihl*4);
    checksum=cal_checksum(ip->ihl*4,temp,0);
    return checksum;
}
uint16_t udp_checksum(struct iphdr *ip,struct udphdr *up,parse *ps)
{
    uint16_t checksum{0};
    //pesudo + udp header + data;

    struct pesudo pu;
    int sum_length= ntohs(up->len) + sizeof(struct pesudo);
    uint8_t temp[sum_length]{0};
    pu.src_ip = ip->saddr;
    pu.dst_ip = ip->daddr;
    pu.reserved=0;
    pu.protocol = ip->protocol;
    pu.length = up->len;
    memcpy(temp,(uint8_t*)&pu,sizeof(struct pesudo));
    up->check=0;
    memcpy(temp+sizeof(struct pesudo),(uint8_t*)up,sizeof(struct udphdr));
    memcpy(temp+sizeof(struct pesudo)+sizeof(struct udphdr),ps->using_dhcp_data(),ps->using_dhcp_data_length());
    bool check;
    if(sum_length%2!=0)
    {
        sum_length++;
        check=true;
    }
    else
        check=false;
    checksum=cal_checksum(sum_length,temp,check);
    return checksum;
}

#endif // CHECKSUM_H
