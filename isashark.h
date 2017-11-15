/*This is header file for source isashark.cpp*/
#ifdef _USE_BSD
#define _USE_BSD
#endif

#ifdef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol
#define SIZE_IP_HDR (20)
#define SIZE_IPV6_HDR (40)

#include <sys/types.h>
#include <stdint.h>
#include <features.h>
#include <sys/socket.h>
#include <stdint.h>

/*this structure is implemented in header file tcp.h*/

typedef uint32_t tcp_seq;

struct tcphdr
  {
    __extension__ union
    {
      struct
      {
       	uint16_t th_sport;	/* source port */
        uint16_t th_dport;	/* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t th_x2:4;        /* (unused) */
        uint8_t th_off:4;	/* data offset */
# endif

# if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t th_off:4;	/* data offset */
        uint8_t th_x2:4;        /* (unused) */
# endif
        uint8_t th_flags;
# define TH_FIN 0x01
# define TH_SYN 0x02
# define TH_RST 0x04
# define TH_PUSH        0x08
# define TH_ACK 0x10
# define TH_URG 0x20
# define TH_CWR 0x80
# define TH_ECE 0x40

        uint16_t th_win;        /* window */
        uint16_t th_sum;        /* checksum */
        uint16_t th_urp;        /* urgent pointer */
      };
      struct
      {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN

        uint16_t res1:4;
        uint16_t doff:4;
        uint16_t fin:1;
        uint16_t syn:1;
        uint16_t rst:1;
        uint16_t psh:1;
        uint16_t ack:1;
        uint16_t urg:1;
        uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
        uint16_t doff:4;
        uint16_t res1:4;
        uint16_t res2:2;
        uint16_t urg:1;
        uint16_t ack:1;
        uint16_t psh:1;
        uint16_t rst:1;
        uint16_t syn:1;
        uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
      };
    };
};

/*this structure is implemented in header file udp.h*/
struct udphdr
{
  __extension__ union
  {
    struct
    {
      uint16_t uh_sport;        /* source port */
      uint16_t uh_dport;        /* destination port */
      uint16_t uh_ulen;         /* udp length */
      uint16_t uh_sum;          /* udp checksum */
    };
    struct
    {
      uint16_t source;
      uint16_t dest;
      uint16_t len;
      uint16_t check;
    };
  };
};

