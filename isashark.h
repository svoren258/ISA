/** 
 * Subject: ISA, Network Applications
 * Project: Network Service Programing - Packet Analyser
 * Author: Ondrej Svoreň, 3 BIT
 * Login: xsvore01
 * Year: 2017/2018
 * File: isashark.h (header file for isashark.cpp)
 **/
#ifdef _USE_BSD
#define _USE_BSD
#endif

#ifdef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)        // offset of Ethernet header to L3 protocol
#define SIZE_IP_HDR (20)          // offset of IPv4 header to L4 protocol
#define SIZE_IPV6_HDR (40)        // offset of IPv6 header to L4 protocol

using namespace std;

/*This class defines all kind of supported protocols attributes and methods, that can be used for output packet description such as
 timestamp, packet length, source MAC address, destionation MAC address, source IP address, destination IP address, time to live (TTL)/hop limit,
 source port number, destination port number, TCP flags, VLAN type and code etc.
 Also includes methods for saving data to the object of current packet for each layer*/
class Packet
{
  public:
    int num;
    long long ts;
    int len;
    string src_mac;
    string dst_mac;
    string vlan_id = "";
    string ipv;
    string ip_addr_src;
    string ip_addr_dst;
    string l4_layer;
    int ttl = -1;
    int hop_limit = -1;
    int src_port = -1;
    int dst_port = -1;
    uint32_t seq_num = -1;
    uint32_t ack_byte = -1;
    string flags = "";
    string icmp_ver = "";
    int icmp_type = -1;
    int icmp_code = -1;
    string type_description = "";
    string code_description = "";
    bool is_unsupported = false;
    bool is_reassembled = false;
    int total_packet_len;
    char *data_buffer;
    void set_values(int packet_num, long long time_stamp, int length);
    void set_L2_layer(string smac, string dmac);
    void set_L3_layer(string ip_v, string ip_src, string ip_dst, int ttl_lim, int hop);
    void set_L4_layer(string l4_id, int s_port, int d_port, uint32_t seq, uint32_t ack, string flgs);
    void set_ICMP(string icmp_v, int type, int code, string type_d, string code_d);
    void output();
    void ttlOrHop();
    void l4_output();
};

/*This class represents aggregated packet and its attributes and methods such as aggregation key,
 number of aggregated packets, size of aggregated packets and method which realizes output*/
class AggregatedPackets {
  public:
    string aggrkey = "";
    int num = 0;
    int size = 0;
    void print_aggr(int limit, bool is_limited, int counter);
};

/*This class describes "hole" in reassembly algorithm implementation.
 Hole is represented by start and end or hole_first and hole_last.*/
class Hole_Descriptor{
  public:
    int hole_first = 0;
    int hole_last = 1023;
    bool actual = true;
};

/*This class represents fragmented packet attributes and methods for manipulation with fragments of the fragmented packet
 such as data buffer, fragment offset or hole_descriptor list, which is type of std::vector working with objects of Hole_Descriptor class.
 Also includes method for creating new fragmented packet and for saving data from current fragment to data buffer*/
class FragmentedPacket: public Packet
 {
   public:
    unsigned short id;
    uint8_t protocol;
    int expected_packet_len = 0;
    int total_packet_len = 0;
    char data_buffer[1024];
    int fragment_offset;
    vector<Hole_Descriptor> hole_descriptor_list;
    void save_data(int offset, char *data, int data_len);
    void create_fragmented_packet(unsigned short id_field, string srcip, string dstip, uint8_t prtcl);
 };


/*In this function is implemented aggregation of packets according to aggr_key - the second parameter and
 the way of putting the packets together and saving them in std::vector, which is used as first parameter*/
void aggregate_packet(vector<AggregatedPackets> *aggr_pac, string aggr_key, int len);

//In this function are saved strings of ICMPv4 and ICMPv6 error messages
void icmp(int version, const u_char *packet, Packet *Pac, int offset);

/*This function describes processing packet on L4 layer, sets transport layer protocol such as TCP, UDP or ICMP according to
 internet protocol version, which is represented by first parameter*/
void l4_protocol(string ipv, const u_char *packet, Packet *Pac, int offset, bool extended_hdr);

/*This function describes processing packet on L3 layer, sets internet protocol version and in case of fragmentation 
 calls function fragmentation_reassembly(..)*/
void l3_protocol(string ip_v, const u_char *packet, Packet *Pac, vector<FragmentedPacket> *frag_packets);

/*This function solves analysis of incoming packets with IPv6 extended headers and jumps over all these headers to
 L4 layer analysis - calls function l4_protocol(..) */
void extended_IPv6_header(const u_char* packet, Packet *Pac);

/*In this function starts reassembly process in case of fragmentation
 The current fragment is verified by comparision of source IP address, destination IP address, identifier and protocol number
 The fragmented packets are saved in std::vector of FragmentedPacket used as last argument and processing continues by 
 calling supplementary function hole_filler(..) */
void fragmentation_reassembly(Packet *Pac, const u_char *packet, string ip_src, string ip_dst, vector<FragmentedPacket> *frag_packets);

/*This function creates object of class FragmentedPacket (1st argument), fulfills empty holes in fragmented packet with data (4th argument) of length total_data_len (2nd argument) 
 from incoming fragment in case of appropriate fragment offset (3rd argument).*/
void hole_filler(FragmentedPacket *Fpac, unsigned int total_data_len, unsigned int fragment_offset, char *data, bool flag_mf);

//Supplementary function used as third parameter of C++ function sort() by sorting
bool sortByBytes(const Packet &p1, const Packet &p2);

//Supplementary function used as third parameter of C++ function sort() by sorting in association with aggregation
bool sortByBytes_a(const AggregatedPackets &p1, const AggregatedPackets &p2);

//supplementary function used as third parameter of C++ function sort() by sorting in association with aggregation
bool sortByPackets(const AggregatedPackets &p1, const AggregatedPackets &p2);

/*This function is looking for ethertype of analysed packet and direct control to functions that are working with upper layer protocols
such as IP, TCP, UDP, ICMP etc. */
void next_header_type(const u_char* packet, Packet *Pac, int offset, vector<FragmentedPacket> *frag_packets);

/*this structure is implemented in header file netinet/tcp.h*/
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

/*this structure is implemented in header file netinet/udp.h*/
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

