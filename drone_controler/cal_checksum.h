#ifndef CAL_CHECKSUM_H
#define CAL_CHECKSUM_H
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include "parse.h"

#pragma pack(push,1)
struct pesudo{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t length;
};
struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t check;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__glibc_reserved;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};
#pragma pack(pop)

class cal_checksum{
  struct iphdr  *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  struct icmphdr *icph;
  struct pesudo pseu;
public:
  cal_checksum();
  void get_iphdr(struct iphdr *ip);
  void get_udphdr(struct udphdr *up);
  void get_tcphdr(struct tcphdr *tp);
  void get_icmphdr(struct icmphdr *icp);
  void get_pesudo(int type);
  uint16_t checksum(int select_checksum);
  uint16_t checksum(int select_checksum, uint8_t *data);
  int calculation(uint8_t *temp, int length, bool change);
};

#endif // CAL_CHECKSUM_H
