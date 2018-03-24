#ifndef CAL_CHECKSUM_H
#define CAL_CHECKSUM_H
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
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

class cal_checksum{
  struct iphdr  *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  struct pesudo pseu;
public:
  cal_checksum();
  void get_iphdr(struct iphdr *ip);
  void get_udphdr(struct udphdr *up);
  void get_tcphdr(struct tcphdr *tp);
  void get_udp_pesudo();
  void get_tcp_pesudo();
  uint16_t checksum(int select_checksum);
  int calculation(uint8_t *temp, int length, bool change);
};

#endif // CAL_CHECKSUM_H
