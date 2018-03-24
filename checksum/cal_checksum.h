#ifndef CAL_CHECKSUM_H
#define CAL_CHECKSUM_H
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "parse.h"

class cal_checksum{
  struct iphdr *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
public:
  cal_checksum();
  void get_iphdr(struct iphdr *ip);
  void get_udphdr(struct udphdr *up);
  void get_tcphdr(struct tcphdr *tp);
  uint16_t checksum(int select_checksum);
  int calculation(uint8_t *temp, int length, bool change);
};

#endif // CAL_CHECKSUM_H
