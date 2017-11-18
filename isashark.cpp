#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h> 
#include <arpa/inet.h>
// #include <linux/if_ether.h>
#include <err.h>
#include <iostream>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sstream>
#include <getopt.h>
// #include <linux/icmp.h>
//#include <linux/if_vlan.h>
//#include <pcap/vlan.h>
//#include <uapi/linux/if_vlan.h>
 // #include <linux/tcp.h>
#include <iomanip>
#include <map>
#include <list>
#include <iterator>
#include <algorithm>
#include <vector>

#ifdef __linux__            // for Linux
// #include <linux/tcp.h>
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
// #include <uapi/linux/if_vlan.h>
#include <linux/if_ether.h>
#endif

#include "isashark.h"

using namespace std;

// #ifndef PCAP_ERRBUF_SIZE
// #define PCAP_ERRBUF_SIZE (256)
// #endif

// #define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol
// #define SIZE_IP_HDR (20)
// #define SIZE_IPV6_HDR (40)


//TCP Flags
// # define TH_FIN 0x01
// # define TH_SYN 0x02
// # define TH_RST 0x04
// # define TH_PUSH        0x08
// # define TH_ACK 0x10
// # define TH_URG 0x20
// # define TH_CWR 0x80
// # define TH_ECE 0x40

//#define ETH_P_8021Q  0x8100 
//#define ETH_P_8021AD 0x88A8 


class AggregatedPackets {
	public:
		string aggrkey = "";
		int num = 0;
		int size = 0;
		// bool is_created = false;
		void print_aggr(int limit, bool is_limited, int counter);
};

void AggregatedPackets::print_aggr(int limit, bool is_limited, int counter) {
	if (this->aggrkey.compare("-1") == 0) {
		return;
		// cerr << "Aggregation fault." << endl;
		// exit(1);
	}

	if ((is_limited) && (counter > limit)) {
		return;
	}
	cout << this->aggrkey << ": " << this->num << " " << this->size << endl;
}

void aggregate_packet(vector<AggregatedPackets> *aggr_pac, string aggr_key, int len){
	// vector<AggregatedPackets> aggr_pac;
	// cout << "values in aggregate_packet: " << aggr_key << " len: " << len << endl;
	// aggr_pac->push_back(AggregatedPackets());
	// AggregatedPackets Pac;
	// aggr_pac->push_back(Pac);
	bool record_exists = false;

	if(aggr_pac->empty()) {
		// cout << "empty" << endl;
		AggregatedPackets Pac;
		Pac.aggrkey = aggr_key;
		Pac.num++;
		Pac.size = len;
		// Pac.is_created = true;
		aggr_pac->push_back(Pac);

		// for (vector<AggregatedPackets>::iterator it = aggr_pac->begin(); it != aggr_pac->end(); ++it) {
		// 	it->print_aggr();
		// 	cout << endl;
		// }
	}
	else {
		for (vector<AggregatedPackets>::iterator it = aggr_pac->begin(); it != aggr_pac->end(); ++it) {
			// cout << "FOR" << endl;
			if (it->aggrkey.compare(aggr_key) == 0) {
				// cout << "IF" << endl;
				it->num++;
				it->size += len;
				record_exists = true;
			}
		}

		if (!record_exists) {
			// cout << "creating new rec" << endl;
			AggregatedPackets Pac;
			Pac.aggrkey = aggr_key;
			Pac.num++;
			Pac.size = len;
			// Pac.is_created = true;
			aggr_pac->push_back(Pac);

			// for (vector<AggregatedPackets>::iterator it = aggr_pac->begin(); it != aggr_pac->end(); ++it) {
			// 	it->print_aggr();
			// 	cout << endl;
			// }
		}
				// exit(1);	
	}
}


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
		string flags;
		string icmp_ver = "";
		int vlan_type = -1;
		int vlan_code = -1;
		string type_description = "";
		string code_description = "";
		bool is_unsupported = false;
		bool is_reassembled = false;
		int total_packet_len;
		//int *data_buffer;
		char *data_buffer;
		void set_values(int packet_num, long long time_stamp, int length);
		void set_L2_layer(string smac, string dmac, string vlanid);
		void set_L3_layer(string ip_v, string ip_src, string ip_dst, int ttl_lim, int hop);
		void set_L4_layer(string l4_id, int s_port, int d_port, uint32_t seq, uint32_t ack, string flgs);
		void set_ICMP(string icmp_v, int type, int code, string type_d, string code_d);
		void output();
		void ttlOrHop();
		void l4_output();
};

void Packet::set_values(int packet_num, long long time_stamp, int length) {
	num = packet_num;
	ts = time_stamp;
	len = length;
}

void Packet::set_L2_layer(string smac, string dmac, string vlanid) {
	src_mac = smac;
	dst_mac = dmac;
	vlan_id = vlanid;
}

void Packet::set_L3_layer(string ip_v, string ip_src, string ip_dst, int ttl_lim, int hop) {
	ipv = ip_v;
	ip_addr_src = ip_src;
	ip_addr_dst = ip_dst;
	ttl = ttl_lim;
	hop_limit = hop;
}

void Packet::set_L4_layer(string l4_id, int s_port, int d_port, uint32_t seq, uint32_t ack, string flgs) {
	l4_layer = l4_id;
	src_port = s_port;		
	dst_port = d_port;
	seq_num = seq;
	ack_byte = ack;
	flags = flgs;
}

void Packet::output() {
	if (this->is_unsupported){
		cout << this->num << ": " << "Unsupported protocol" << endl;
	}
	else {
		cout << this->num << ": " << this->ts << " " << this->len << " | " << "Ethernet: " << this->src_mac << " " << this->dst_mac << " " << this->vlan_id << "| " << this->ipv << ": " << this->ip_addr_src << " " << this->ip_addr_dst << " ";				// for (int k = 1; k < my_map.size()+1; k++) {
		this->ttlOrHop();
		cout << " | ";
		this->l4_output();
	}	
}

void Packet::ttlOrHop() {
	if (this->ttl != -1) {
		cout << this->ttl;
	}
	else if (this->hop_limit != -1) {
		cout << this->hop_limit;
	}
}

void Packet::l4_output() {
	cout << this->l4_layer;
	if (this->src_port != -1) {
		cout << this->src_port;
		cout << " ";
	}

	if (this->dst_port != -1) {
		cout << this->dst_port;
		cout << " ";
	}

	if (this->seq_num != -1) {
		cout << this->seq_num;
		cout << " ";
	}

	if (this->ack_byte != -1) {
		cout << this->ack_byte;
		cout << " ";
	}

	if (this->flags.compare("") != 0) {
		cout << this->flags;
	}
	
	if (this->icmp_ver.compare("") != 0) {
		cout << this->icmp_ver;
	}

	if (this->vlan_type != -1) {
		cout << this->vlan_type;
		cout << " ";
	}

	if (this->vlan_code != -1) {
		cout << this->vlan_code;
		cout << " ";
	}

	if (this->type_description.compare("") != 0) {
		cout << this->type_description;
		cout << " ";
	}

	if (this->code_description.compare("") != 0) {
		cout << this->code_description;
	}

	cout << endl;
}

void Packet::set_ICMP(string icmp_v, int type, int code, string type_d, string code_d) {
	icmp_ver = icmp_v;
	vlan_type = type;
	vlan_code = code;
	type_description = type_d;
	code_description = code_d; 
}

void icmp(int version, const u_char *packet, Packet *Pac, int offset = 0) {

	struct icmp* my_icmp;
	struct icmp6_hdr* my_icmp6;

	int type = -1;
	int code = -1;
	string icmp_ver;
	string type_description = "";
	string code_description = "";

	if (version == 6) {

		icmp_ver = "ICMPv6: ";
		my_icmp6 = (struct icmp6_hdr*)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR+offset);
		type = my_icmp6->icmp6_type;
		code = my_icmp6->icmp6_code;

		if (type == 1){
			// cout << "destinaton unreachable ";
			type_description = "Destination unreachable";
			switch(code) {
				case 0:
					// cout << "no route destination" << endl;
					code_description = "no route to destination";
					break;

				case 1:
					// cout << "communication with destination administratively prohibited" << endl;
					code_description = "communication with destination administratively prohibited";
					break;

				case 2:
					// cout << "beyond scope of source address" << endl;
					code_description = "beyond scope of source address";
					break;

				case 3:
					// cout << "address unreachable" << endl;
					code_description = "address unreachable";
					break;

				case 4:
					// cout << "port unreachable" << endl;
					code_description = "port unreachable";
					break;

				case 5:
					// cout << "source address failed ingress/engress policy" << endl;
					code_description = "source address failed ingress/engress policy";
					break;

				case 6:
					// cout << "reject route to destination" << endl;
					code_description = "reject route to destination";
					break;

				case 7:
					code_description = "error in source routing header";
					break;
			}
		}

		else if (type == 2) {
			// cout << "packet too big" << endl;
			type_description = "Packet too big";
		}

		else if (type == 3) {
			// cout << "time exceeded ";
			type_description = "Time exceeded";
			if (code == 0) {
				// cout << "hop limit exceeded in transit" << endl;
				code_description = "hop limit exceeded in transit";
			}

			else if (code == 1) {
				// cout << "fragment reassembly time exceeded" << endl;
				code_description = "fragment reassembly time exceeded";
			}
		}

		else if (type == 4) {
			// cout << "parameter problem ";
			type_description = "Parameter problem";
			switch(code) {
				case 0:
					// cout << "roneous header field encountered" << endl;
					code_description = "erroneous header field encountered";
					break;

				case 1:
					// cout << "unrecognized Next Header type encountered" << endl;
					code_description = "unrecognized Next Header type encountered";
					break;

				case 2:
					// cout << "unrecognized IPv6 option encountered" << endl;
					code_description = "unrecognized IPv6 option encountered";
					break;
			}
		}

		else if ((type == 100) || (type == 101) || (type == 200) || (type == 201)) {
			// cout << "private experimentation ";
			type_description = "Private experimentation";
		}

		else if (type == 128) {
			type_description = "Echo Request";
		}

		else if (type == 129) {
			type_description = "Echo Reply";
		}
	}
	else if (version == 4) {
		icmp_ver = "ICMPv4: ";
		if (Pac->is_reassembled) {
			my_icmp = (struct icmp*)(Pac->data_buffer);
		}
		else {
			my_icmp = (struct icmp*)(packet+SIZE_ETHERNET+SIZE_IP_HDR);
		}
		type = my_icmp->icmp_type;
		code = my_icmp->icmp_code;

		if (type == 0) {
			// cout << "echo message" << endl;
			type_description = "echo reply message";
		}

		else if (type == 3) {
			switch(code) {
				case 0:
					// cout << "net unreachable" << endl;
					code_description = "net unreachable";
					break;

				case 1:
					// cout << "host unreachable" << endl;
					code_description = "host unreachable";
					break;

				case 2:
					// cout << "protocol unreachable" << endl;
					code_description = "protocol unreachable";
					break;

				case 3:
					// cout << "port unreachable" << endl;
					code_description = "port unreachable";
					break;

				case 4:
					// cout << "fragmentation needed and DF set" << endl;
					code_description = "fragmentation needed and DF set";
					break;

				case 5:
					// cout << "source route failed" << endl;
					code_description = "source route failed";
					break;

				case 6:
					code_description = "destination network unknown";
					break;

				case 7:
					code_description = "destination host unknown";
					break;

				case 8:
					code_description = "source host isolated";
					break;

				case 9:
					code_description = "network administratively prohibited";
					break;

				case 10:
					code_description = "host administratively prohibited";
					break;

				case 11:
					code_description = "network unreachable for Type of Service";
					break;

				case 12:
					code_description = "host unreachable for Type of Service";
					break;

				case 13:
					code_description = "communication administratively prohibited";
					break;

				case 14:
					code_description = "host precedence violation";
					break;

				case 15:
					code_description = "precedence cutoff in effect";
					break;
			}
		}
		else if (type == 5) {
			switch(code) {
				case 0:
					// cout << "redirect datagrams for the Network" << endl;
					code_description = "Redirect datagrams for the Network";
					break;

				case 1:
					// cout << "redirect datagrams for the Host" << endl;
					code_description = "Redirect datagrams for the Host";
					break;

				case 2:
					// cout << "redirect datagrams for the Type of Service and Network" << endl;
					code_description = "Redirect datagrams for the Type of Service and Network";
					break;

				case 3:
					// cout << "redirect datagrams for the Type of Service and Host" << endl;
					code_description = "Redirect datagrams for the Type of Service and Host";
					break;
			}
		}
		else if (type == 8) {
			// cout << "echo reply message" << endl;
			type_description = "echo message";
		}

		else if (type == 9) {
			type_description = "router advertisment";
		}

		else if (type == 10) {
			type_description = "router solicitation";
		}

		else if (type == 11) {
			if (code == 0) {
				// cout << "time to live exceeded in transit" << endl;
				code_description = "time to live exceeded in transit";
			}
			else if (code == 1) {
				// cout << "fragment reassembly time exceeded" << endl;
				code_description = "fragment reassembly time exceeded";
			}
		}
		else if (type == 12) {
			// cout << "parameter problem ";
			if (code == 0) {
				// cout << "pointer indicates error" << endl;
				code_description = "pointer indicates the error";
			}

			else if (code == 1) {
				code_description = "missing a required option";
			}

			else if (code == 2) {
				code_description = "bad length";
			}
		} 
		else if (type == 13) {
			// cout << "timestamp message" << endl;
			type_description = "timestamp message";
		}
		else if (type == 14) {
			// cout << "timestamp reply message" << endl;
			type_description = "timestamp reply message";
		}
		else if (type == 15) {
			// cout << "information request message" << endl;
			type_description = "information request message";
		} 
		else if (type == 16) {
			// cout <<  "information reply message" << endl;
			type_description = "information reply message";
		}		
		else if (type == 17) {
			type_description = "address mask request";
		}

		else if (type == 18) {
			type_description = "addres mask reply";
		}
	}

	Pac->set_ICMP(icmp_ver, type, code, type_description, code_description);
}

// static int total_offset = 0;
// static bool extended_hdr = false;

void l4_protocol(string ipv, const u_char *packet, Packet *Pac, int offset, bool extended_hdr);

void extended_IPv6_header(uint8_t next, const u_char* packet, Packet *Pac) {

	struct ip6_ext *my_ip6_ext;
	int total_offset = 0;
	//int x = 0;
	bool extended_hdr = false;
	// struct ip6_hdr *my_ip6;
	my_ip6_ext = (struct ip6_ext*)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR);
	// printf("next: %x\n",  my_ip6_ext->ip6e_nxt);
	// printf("len: %x\n",  my_ip6_ext->ip6e_len);
	while (total_offset < Pac->len) {
		// cout << "total offset: " << total_offset << endl;
		if ((my_ip6_ext->ip6e_nxt == 6) || (my_ip6_ext->ip6e_nxt == 17) || (my_ip6_ext->ip6e_nxt == 58)) {
			// printf("my_ip6_ext: %x\n", my_ip6_ext->ip6e_nxt);
			// printf("my_ip6_hdr: %x\n", my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
			extended_hdr = true;
			l4_protocol("IPv6", packet, Pac, total_offset+34, extended_hdr);
			//pac->output();
			break;
		} 
		else {
			total_offset += 8*(1+(int)my_ip6_ext->ip6e_len);
			my_ip6_ext = (struct ip6_ext*)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR+total_offset);
			// my_ip6 = (struct ip6_hdr*)(packet+SIZE_ETHERNET+34+total_offset);	
		}
		//x += total_offset;
	}	
	
	if (!extended_hdr) {
		Pac->is_unsupported = true;
		// cerr << "Unsupported L4 layer protocol" << endl;
		// exit(1);	
	}
}

void l4_protocol(string ipv, const u_char *packet, Packet *Pac, int offset = 0, bool extended_hdr = false) {

	struct tcphdr *my_tcp;
	struct udphdr *my_udp;

	struct ip* my_ip;
	struct ip6_hdr* my_ip6;

	struct ip6_opt* my_ip6_opt;
	struct ip6_hbh* my_ip6_hbh;
	struct ip6_dest* my_ip6_dest;
	struct ip6_ext* my_ip6_ext;
	struct ip6_rthdr* my_ip6_rthdr;


	my_ip = (struct ip*)(packet+SIZE_ETHERNET);        // skip Ethernet header
	my_ip6 = (struct ip6_hdr*)(packet+SIZE_ETHERNET+offset);

	int src_port = -1;
	int dst_port = -1;
	uint32_t ack_byte = -1;
	uint32_t seq_num = -1;
	string l4_id;
	string flags = "";
	// cout << ipv << endl;

	if (ipv.compare("IPv4") == 0) {

		switch (my_ip->ip_p) {
			case 1:
				icmp(4, packet, Pac);
				break;
				
			case 6:
				l4_id = "TCP: ";
				cout << "TCP" << endl;
				if (Pac->is_reassembled) {
						// printf("Pac data buffer: %s\n", Pac->data_buffer);
					cout << "is_reassembled" << endl;
					my_tcp = (struct tcphdr *)(Pac->data_buffer);
				}
				else {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+SIZE_IP_HDR); // pointer to the TCP header
				}
				// my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+SIZE_IP_HDR); // pointer to the TCP header
				// cout << ntohs(my_tcp->th_sport) << " " << ntohs(my_tcp->th_dport) << " " << my_tcp->th_seq << " " << my_tcp->th_ack << " ";
				src_port = ntohs(my_tcp->th_sport);
				dst_port = ntohs(my_tcp->th_dport);
				// seq_num = (my_tcp->th_seq);
				// ack_byte = (my_tcp->th_ack);
				seq_num = htonl(my_tcp->th_seq);
				ack_byte = htonl(my_tcp->th_ack);

				if (my_tcp->th_flags & TH_CWR){
					// cout << "C";
					flags = flags + "C";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ECE){
					// cout << "E";
					flags = flags + "E";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_URG){
					// cout << "U";
					flags = flags + "U";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ACK){
					// cout << "A";	
					flags = flags + "A";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_PUSH){
					// cout << "P";
					flags = flags + "P";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_RST){
					// cout << "R";
					flags = flags + "R";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_SYN){
					// cout << "S";
					flags = flags + "S";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_FIN){
					// cout << "F";
					flags = flags + "F";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				// cout << endl;

				break;

				case 17:
					// cout << "UDP: ";
					l4_id = "UDP: ";
					cout << "UDP" << endl;
					if (Pac->is_reassembled) {
						// printf("Pac data buffer: %s\n", Pac->data_buffer);
						cout << "is_reassembled" << endl;
						my_udp = (struct udphdr *)(Pac->data_buffer);
					}
					else {
						my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+SIZE_IP_HDR); // pointer to the UDP header
					}
					// cout << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
					src_port = ntohs(my_udp->uh_sport);
					dst_port = ntohs(my_udp->uh_dport);
					break;

				default:
					Pac->is_unsupported = true;
					// cerr << "Unsupported L4 layer protocol" << endl;
					// exit(1);
					break;
			}
	}

	else if (ipv.compare("IPv6") == 0) {
		uint8_t next_hdr = my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		switch (my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
			case 6:
				// cout << "tcp" << endl;
				// cout << "offset: " << offset << endl;
				l4_id = "TCP: ";
				if (extended_hdr) {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+offset+14); // pointer to the TCP header
				}
				else {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+SIZE_IPV6_HDR); // pointer to the TCP header
				}
				// cout << ntohs(my_tcp->th_sport) << " " << ntohs(my_tcp->th_dport) << " " << my_tcp->th_seq << " " << my_tcp->th_ack << " ";
				src_port = ntohs(my_tcp->th_sport);
				dst_port = ntohs(my_tcp->th_dport);
				seq_num = htonl(my_tcp->th_seq);
				ack_byte = htonl(my_tcp->th_ack);

				if (my_tcp->th_flags & TH_CWR){
					// cout << "C";
					flags = flags + "C";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ECE){
					// cout << "E";
					flags = flags + "E";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_URG){
					// cout << "U";
					flags = flags + "U";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ACK){
					// cout << "A";	
					flags = flags + "A";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_PUSH){
					// cout << "P";
					flags = flags + "P";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_RST){
					// cout << "R";
					flags = flags + "R";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_SYN){
					// cout << "S";
					flags = flags + "S";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_FIN){
					// cout << "F";
					flags = flags + "F";
				}
				else{
					// cout << ".";
					flags = flags + ".";
				}
				// cout << endl;
				if (extended_hdr) {
					Pac->set_L4_layer(l4_id, src_port, dst_port, seq_num, ack_byte, flags);
				}
				break;
	    
		    case 17:
		    	if (extended_hdr) {
					my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+offset+14); // pointer to the TCP header
				}
				else {
	    			my_udp = (struct udphdr *)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR); // pointer to the UDP header	
				}
	    		// cout << "UDP: " << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
	    		l4_id = "UDP: ";
	    		src_port = ntohs(my_udp->uh_sport);
	    		dst_port = ntohs(my_udp->uh_dport);
	    		//pac->set_L4_layer(l4_protocol, src_port, dst_port, seq_num, ack_byte, flags);
	    		if (extended_hdr) {
					Pac->set_L4_layer(l4_id, src_port, dst_port, seq_num, ack_byte, flags);
				}
	    		break;

	    	case 58:
	    		if (extended_hdr) {
	    			icmp(6, packet, Pac, offset+14);
	    		}
	    		else {
	    			icmp(6, packet, Pac);
	    		}
	    		break;

	    	default:
	    		extended_IPv6_header(next_hdr, packet, Pac);
	    		//pac->output();
	    		break;
    	}
	}

	//pac->output();
	if ((!extended_hdr) && (src_port != -1)) {
		Pac->set_L4_layer(l4_id, src_port, dst_port, seq_num, ack_byte, flags);
	}

}


class Hole_Descriptor{
	public:
		int hole_first = 0;
		int hole_last = 1023;
		bool actual = true;
};


 class FragmentedPacket: public Packet
 {
	 public:
	 	int packet_id;
	 	unsigned short id;
	 	// string src_ip;
	 	// string dst_ip;
	 	uint8_t protocol;
	 	//reassembly process variables
	 	int expected_packet_len = 0;
	 	int total_packet_len = 0;
	 	//int data_buffer[1024];
	 	char data_buffer[1024];
	 	int fragment_offset;
	 	// bool is_reassembled = false;
	 	// int num_of_fragments = 0;
	 	//unsigned int timer; //15s ?
	 	// char *data_buffer;

	 	vector<Hole_Descriptor> hole_descriptor_list;
	 	// void save_data(int offset, int *data, int data_len);
	 	void save_data(int offset, char *data, int data_len);
	 	void create_fragmented_packet(unsigned short id_field, string srcip, string dstip, uint8_t prtcl);

 };

 void FragmentedPacket::create_fragmented_packet(unsigned short id_field, string srcip, string dstip, uint8_t prtcl) {
 	id = id_field;
 	ip_addr_src = srcip;
 	ip_addr_dst = dstip;
 	protocol = prtcl;
 }

static int packet_id = 0;

// int size_of_array(int *array) {
// 	return sizeof(array)/sizeof(array[0]);
// }

// void array_to_array(int *dst, int *src, int len) {
// 	for (int i = 0; i < len; i++) {
// 		dst[i] = src[i];
// 	}
// }


void array_to_array(char *dst, char *src, int len) {
	for (int i = 0; i < len; i++) {
		dst[i] = src[i];
	}
}
// void FragmentedPacket::save_data(int offset, int *data, int data_len) {
// 	//int array_len = size_of_array(data);
// 	for(int x = 0; x < data_len; x++) {
// 		this->data_buffer[x+offset] = data[x];
// 		printf("%x ", this->data_buffer[x+offset]);
// 	}
// 	cout << endl;
// 	// for (int k = offset; k < offset+sizeof(this->data_buffer); k++) {
// 	// 	printf("%x ", this->data_buffer[k]);
// 	// 	if (k % 8 == 0) {
// 	// 		cout << endl;
// 	// 	}
// 	// }
// 	// cout << endl;
// 	// printf("DATA: %s\n", this->data_buffer);
// }

void FragmentedPacket::save_data(int offset, char *data, int data_len) {
	//int array_len = size_of_array(data);
	for(int x = 0; x < data_len; x++) {
		this->data_buffer[x+offset] = data[x];
		printf("%x ", this->data_buffer[x+offset]);
	}
	cout << endl;
	// for (int k = offset; k < offset+sizeof(this->data_buffer); k++) {
	// 	printf("%x ", this->data_buffer[k]);
	// 	if (k % 8 == 0) {
	// 		cout << endl;
	// 	}
	// }
	// cout << endl;
	// printf("DATA: %s\n", this->data_buffer);
}

void fragmentation_reassembly(Packet *Pac, const u_char *packet, string ip_src, string ip_dst, vector<FragmentedPacket> *frag_packets) {
	struct ip* my_ip;
	my_ip = (struct ip*)(packet+SIZE_ETHERNET);
	// unsigned int total_len = int(packet[17]); // size of ip datagram (header+data)
	unsigned int total_data_len = int(packet[17]) - SIZE_IP_HDR;
	// bool changed = false;
	bool exists = false;
	bool fragment_exists = false;
	// bool flag_mf = int(packet[20]) != 0;
	bool flag_mf = int(packet[20]) & 0x20;
	unsigned int fragment_offset = int(packet[21]) << 3;
	//int data[total_data_len];
	int data_len;
	char data[total_data_len];
	// int data_buffer[1024];
	cout << "DATA: ";
	for (int x = 0; x < total_data_len; ++x) {
		data[x] = packet[Pac->len-total_data_len+x];
		// printf("%x ", data[x]);
	}
	cout << endl;
	data_len = sizeof(data)/sizeof(data[0]);
	// cout << "data size: " << data_len << endl;
	// for (int y = 0; y < strlen(data); y++) {
	// 	printf("%c", data[y]);
	// }
	// cout << endl;

	printf("DATA: %s\n", data);
	// memcpy(data_buffer, data, strlen(data)+1);
	// // printf("strlen data_buffer: %d\n", strlen(data_buffer));
	// printf("DATA_BUFFER: %s\n", data_buffer);

	// int packet_id = 0;


	// cout << "total_len: " << total_len << endl;
	// cout << "total_data_len: " << total_data_len << endl;

	if(frag_packets->empty()) {
		cout << "Creating new frag_packet" << endl;
		// cout << "empty" << endl;
		FragmentedPacket FPac;
		FPac.packet_id = packet_id++;
		cout << "Packet ID: " << FPac.packet_id << endl;
		FPac.create_fragmented_packet(my_ip->ip_id, ip_src, ip_dst, my_ip->ip_p);
		FPac.fragment_offset = fragment_offset;
		Hole_Descriptor Hole;
		FPac.hole_descriptor_list.push_back(Hole);
		for(vector<Hole_Descriptor>::iterator i = FPac.hole_descriptor_list.begin(); i != FPac.hole_descriptor_list.end(); ++i) {
			if (!i->actual) {
				cout << "not actual" << endl;
				continue;
			}
			if (!flag_mf) {
				FPac.expected_packet_len = fragment_offset+total_data_len;
				// i->hole_last = fragment_offset;
				cout << "expected packet len: " << FPac.expected_packet_len << endl;
			}
			cout << "hole first: " << i->hole_first << endl;
			cout << "hole last: " << i->hole_last << endl;
			cout << "fragment first: " << fragment_offset << endl;
			cout << "fragment last: " << fragment_offset+total_data_len-1 << endl;
			if ((i->hole_first > fragment_offset) || (i->hole_last < fragment_offset+total_data_len-1)) {
				continue;
			}
			else if (i->hole_first < fragment_offset) {
				i->actual = false;
				Hole_Descriptor NewHole;
				NewHole.hole_first = i->hole_first;
				NewHole.hole_last = fragment_offset-1;
				cout << "new hole first: " << NewHole.hole_first << endl;
				cout << "new hole last: " << NewHole.hole_last << endl;
				// cout << "skuska hole last " << i->hole_last << endl;

				if (i->hole_last > fragment_offset+total_data_len-1) {
					// changed = true;
					Hole_Descriptor NewHole2;
					NewHole2.hole_first = fragment_offset+total_data_len;
					NewHole2.hole_last = i->hole_last;
					cout << "new hole2 first: " << NewHole2.hole_first << endl;
					cout << "new hole2 last: " << NewHole2.hole_last << endl;
					FPac.hole_descriptor_list.push_back(NewHole2);
				}
				// if(!changed) {
				// 	FPac.hole_descriptor_list.pop_back();
				// }
				FPac.hole_descriptor_list.push_back(NewHole);
				FPac.total_packet_len += total_data_len;
				// FPac.save_data(fragment_offset, data, data_len);
				FPac.save_data(fragment_offset, data, total_data_len);
				//size_t index = distance(it->hole_descriptor_list.begin(), i);
				//i = it->hole_descriptor_list.erase(i);

				// it->hole_descriptor_list.erase(it->hole_descriptor_list.begin());
				//cout << "data len " << total_data_len << endl;
					// it->total_packet_len += total_data_len;
				break;
			}

			else if (i->hole_first == fragment_offset) {
				if (i->hole_last == fragment_offset+total_data_len-1) {
					i->actual = false;
					cout << "XXX" << endl;
					FPac.total_packet_len += total_data_len;
					//FPac.save_data(fragment_offset, data, data_len);
					FPac.save_data(fragment_offset, data, total_data_len);
				}
				else {
					i->hole_first = fragment_offset+total_data_len;
					cout << "changed hole_first: " << i->hole_first << endl;
					FPac.total_packet_len += total_data_len;
					//FPac.save_data(fragment_offset, data, data_len);
					FPac.save_data(fragment_offset, data, total_data_len);
				}

				break;
			}
			else if (i->hole_last == fragment_offset+total_data_len-1) {
				i->hole_last = fragment_offset-1;
				cout << "changed hole_last: " << i->hole_last << endl;
				FPac.total_packet_len += total_data_len;
				// FPac.save_data(fragment_offset, data, data_len);
				FPac.save_data(fragment_offset, data, total_data_len);
				break;
			}
		}
		// if (FPac.expected_packet_len == FPac.total_packet_len) {
		// 	Pac->is_reassembled = true;
		// 	cout << "total packet len " << FPac.total_packet_len << endl;
		// 	break;
		// }	
		cout << "packet len " << FPac.total_packet_len << endl;
		frag_packets->push_back(FPac);

	}
	else {
		for (vector<FragmentedPacket>::iterator it = frag_packets->begin(); it != frag_packets->end(); ++it) {
			
			if ((it->id == my_ip->ip_id) && (it->ip_addr_src.compare(ip_src) == 0) && (it->ip_addr_dst.compare(ip_dst) == 0) && (it->protocol == my_ip->ip_p)) {
				// for(vector<int>::iterator i = it->hole_descriptors.begin(); i != it->hole_descriptors.end(); ++i) {
				cout << "Packet ID: " << it->packet_id << endl;
				cout << "Exists in frag_packets!" << endl;
				exists = true;
			
				for(vector<Hole_Descriptor>::iterator i = it->hole_descriptor_list.begin(); i != it->hole_descriptor_list.end(); ++i) {
					if (!i->actual) {
						cout << "not actual" << endl;
						continue;
					}
					if (!flag_mf) {
						it->expected_packet_len = fragment_offset+total_data_len;
						// i->hole_last = fragment_offset;
						cout << "expected packet len: " << it->expected_packet_len << endl;
					}
					cout << "hole first: " << i->hole_first << endl;
					cout << "hole last: " << i->hole_last << endl;
					cout << "fragment first: " << fragment_offset << endl;
					cout << "fragment last: " << fragment_offset+total_data_len-1 << endl;
					if ((i->hole_first > fragment_offset) || (i->hole_last < fragment_offset+total_data_len-1)) {
						continue;
					}
					else if (i->hole_first < fragment_offset) {
						i->actual = false;
						Hole_Descriptor NewHole;
						NewHole.hole_first = i->hole_first;
						NewHole.hole_last = fragment_offset-1;
						cout << "new hole first: " << NewHole.hole_first << endl;
						cout << "new hole last: " << NewHole.hole_last << endl;
						// cout << "skuska hole last " << i->hole_last << endl;

						if (i->hole_last > fragment_offset+total_data_len-1) {
							// changed = true;
							Hole_Descriptor NewHole2;
							NewHole2.hole_first = fragment_offset+total_data_len;
							NewHole2.hole_last = i->hole_last;
							cout << "new hole2 first: " << NewHole2.hole_first << endl;
							cout << "new hole2 last: " << NewHole2.hole_last << endl;
							it->hole_descriptor_list.push_back(NewHole2);
						}
					
						it->hole_descriptor_list.push_back(NewHole);
						it->total_packet_len += total_data_len;
						// it->save_data(fragment_offset, data, data_len);
						//size_t index = distance(it->hole_descriptor_list.begin(), i);
						it->save_data(fragment_offset, data, total_data_len);

						//i = it->hole_descriptor_list.erase(i);

						// it->hole_descriptor_list.erase(it->hole_descriptor_list.begin());
						//cout << "data len " << total_data_len << endl;
						break;
					}

					else if (i->hole_first == fragment_offset) {
						if (i->hole_last == fragment_offset+total_data_len-1) {
							i->actual = false;
							cout << "XXX" << endl;
							it->total_packet_len += total_data_len;
							// it->save_data(fragment_offset, data, data_len);
							it->save_data(fragment_offset, data, total_data_len);
						}
						else {
							i->hole_first = fragment_offset+total_data_len;
							cout << "changed hole_first: " << i->hole_first << endl;
							it->total_packet_len += total_data_len;
							// it->save_data(fragment_offset, data, data_len);
							it->save_data(fragment_offset, data, total_data_len);
						}

						break;
					}
					else if (i->hole_last == fragment_offset+total_data_len-1) {
						i->hole_last = fragment_offset-1;
						cout << "changed hole_last: " << i->hole_last << endl;
						it->total_packet_len += total_data_len;
						// it->save_data(fragment_offset, data, data_len);
						it->save_data(fragment_offset, data, total_data_len);
						break;
					}
				}

				if (it->expected_packet_len == it->total_packet_len) {
					
					Pac->is_reassembled = true;

					Pac->total_packet_len = it->total_packet_len;
					//Pac->data_buffer = new int[it->total_packet_len];
					Pac->data_buffer = new char[it->total_packet_len];
					array_to_array(Pac->data_buffer, it->data_buffer, it->total_packet_len);
					cout << "Total packet length is: " << it->total_packet_len << endl;
				
					
					cout << endl;
					break;
				}		

				cout << "packet len " << it->total_packet_len << endl;
				break;
			}

			
			
			
		}
		if ((!exists) && (!Pac->is_reassembled)) {
			cout << "Creating new frag_packet" << endl;
			FragmentedPacket FPac;
			FPac.packet_id = packet_id++;
			cout << "Packet ID: " << FPac.packet_id << endl;
			FPac.create_fragmented_packet(my_ip->ip_id, ip_src, ip_dst, my_ip->ip_p);
			FPac.fragment_offset = fragment_offset;
			Hole_Descriptor Hole;
			FPac.hole_descriptor_list.push_back(Hole);
			for(vector<Hole_Descriptor>::iterator i = FPac.hole_descriptor_list.begin(); i != FPac.hole_descriptor_list.end(); ++i) {
				if (!i->actual) {
					cout << "not actual" << endl;
					continue;
				}
				if (!flag_mf) {
					FPac.expected_packet_len = fragment_offset+total_data_len;
					// i->hole_last = fragment_offset;
					cout << "expected packet len: " << FPac.expected_packet_len << endl;
				}
				cout << "hole first: " << i->hole_first << endl;
				cout << "hole last: " << i->hole_last << endl;
				cout << "fragment first: " << fragment_offset << endl;
				cout << "fragment last: " << fragment_offset+total_data_len-1 << endl;
				if ((i->hole_first > fragment_offset) || (i->hole_last < fragment_offset+total_data_len-1)) {
					continue;
				}
				else if (i->hole_first < fragment_offset) {
					i->actual = false;
					Hole_Descriptor NewHole;
					NewHole.hole_first = i->hole_first;
					NewHole.hole_last = fragment_offset-1;
					cout << "new hole first: " << NewHole.hole_first << endl;
					cout << "new hole last: " << NewHole.hole_last << endl;
					// cout << "skuska hole last " << i->hole_last << endl;

					if (i->hole_last > fragment_offset+total_data_len-1) {
						// changed = true;
						Hole_Descriptor NewHole2;
						NewHole2.hole_first = fragment_offset+total_data_len;
						NewHole2.hole_last = i->hole_last;
						cout << "new hole2 first: " << NewHole2.hole_first << endl;
						cout << "new hole2 last: " << NewHole2.hole_last << endl;
						FPac.hole_descriptor_list.push_back(NewHole2);
					}
					// if(!changed) {
					// 	FPac.hole_descriptor_list.pop_back();
					// }
					FPac.hole_descriptor_list.push_back(NewHole);
					FPac.total_packet_len += total_data_len;
					// FPac.save_data(fragment_offset, data, data_len);
					FPac.save_data(fragment_offset, data, total_data_len);

					//size_t index = distance(it->hole_descriptor_list.begin(), i);
					//i = it->hole_descriptor_list.erase(i);

					// it->hole_descriptor_list.erase(it->hole_descriptor_list.begin());
					//cout << "data len " << total_data_len << endl;
						//it->total_packet_len += total_data_len;
					break;
				}

				else if (i->hole_first == fragment_offset) {
					if (i->hole_last == fragment_offset+total_data_len-1) {
						i->actual = false;
						cout << "XXX" << endl;
						FPac.total_packet_len += total_data_len;
						// FPac.save_data(fragment_offset, data, data_len);
						FPac.save_data(fragment_offset, data, total_data_len);
					}
					else {
						i->hole_first = fragment_offset+total_data_len;
						cout << "changed hole_first: " << i->hole_first << endl;
						FPac.total_packet_len += total_data_len;
						// FPac.save_data(fragment_offset, data, data_len);
						FPac.save_data(fragment_offset, data, total_data_len);
					}
					break;
				}
				else if (i->hole_last == fragment_offset+total_data_len-1) {
					i->hole_last = fragment_offset-1;
					cout << "changed hole_last: " << i->hole_last << endl;
					FPac.total_packet_len += total_data_len;
					// FPac.save_data(fragment_offset, data, data_len);
					FPac.save_data(fragment_offset, data, total_data_len);
					break;
				}
			}
			// if (FPac.expected_packet_len == FPac.total_packet_len) {
			// 	Pac->is_reassembled = true;
			// 	cout << "total packet len " << FPac.total_packet_len << endl;
			// 	break;
			// }	
			cout << "packet len " << FPac.total_packet_len << endl;
			frag_packets->push_back(FPac);	
		}
	}
}

void l3_protocol(string ip_v, const u_char *packet, Packet *Pac, vector<FragmentedPacket> *frag_packets = 0) {
	// #define _USE_BSD
	// #define __FAVOR_BSD
	string ipv;
	char ip_addr_src_ch[40];
	string ip_addr_src;
	char ip_addr_dst_ch[40];
	string ip_addr_dst;
	int ttl = -1;
	int hop_limit = -1;
	u_int size_ip;

	const struct tcphdr *my_tcp;
	const struct udphdr *my_udp;

	struct ip *my_ip;
	struct ip6_hdr *my_ip6;

	my_ip = (struct ip*)(packet+SIZE_ETHERNET);
	bool flag_mf = int(packet[20]) & 0x20;
	// bool flag_mf = int(packet[20]) != 0;
	unsigned int fragment_offset = int(packet[21]) << 3;

	my_ip6 = (struct ip6_hdr*)(packet+SIZE_ETHERNET);

	/*
	TCP_FLAG_CWR = __constant_cpu_to_be32(0x00800000),
    TCP_FLAG_ECE = __constant_cpu_to_be32(0x00400000),
    TCP_FLAG_URG = __constant_cpu_to_be32(0x00200000),
    TCP_FLAG_ACK = __constant_cpu_to_be32(0x00100000),
    TCP_FLAG_PSH = __constant_cpu_to_be32(0x00080000),
    TCP_FLAG_RST = __constant_cpu_to_be32(0x00040000),
    TCP_FLAG_SYN = __constant_cpu_to_be32(0x00020000),
    TCP_FLAG_FIN = __constant_cpu_to_be32(0x00010000),
	*/

	if (ip_v.compare("IPv4") == 0) {
		//ipv = "IPv4";
		// size_ip = my_ip->ip_hl*4;                           // length of IP header

		// printf("total len: %d\n", total_len);
		// printf("identification: %d\n", my_ip->ip_id);
		printf("offset: %d\n", fragment_offset);

		// for(int i = 34; i < 42; i++) {
		// 	printf("data: %x\n", packet[i]);
		// }
		//printf("data len: %d\n", (int)packet[17] - SIZE_IP_HDR);
		// //printf("offset: %d\n", my_ip->ip_off);
		// // printf("srcip: %s\n", inet_ntoa(my_ip->ip_src));
		// // printf("ip_prot: %d\n", my_ip->ip_p);
		// // // printf("offmask: %d\n", (my_ip->ip_off & IP_OFFMASK));
		// // // printf("MF: %d\n", (my_ip->ip_off & IP_MF));
		// // if(flag_mf) {
		// // 	cout << "1" << endl;
		// // }
		// // else {
		// // 	cout << "0" << endl;
		// // }

		printf("flag mf: %d\n", flag_mf);

		
		snprintf(ip_addr_src_ch, sizeof(ip_addr_src_ch), "%s", inet_ntoa(my_ip->ip_src));
		ip_addr_src = ip_addr_src_ch;

		snprintf(ip_addr_dst_ch, sizeof(ip_addr_dst_ch), "%s", inet_ntoa(my_ip->ip_dst));
		ip_addr_dst = ip_addr_dst_ch;

		ttl = my_ip->ip_ttl;
		
		if ((flag_mf) || (fragment_offset != 0)) {
			// Pac->is_reassembled = false;
			//printf("data len: %d\n", (int)packet[17] - SIZE_IP_HDR);
			fragmentation_reassembly(Pac, packet, ip_addr_src, ip_addr_dst, frag_packets);
			// for(vector<FragmentedPacket>::iterator it = frag_packets->begin(); it != frag_packets->end(); ++it) {
			// 	cout << it->ip_addr_src << endl;
			// }
		}
		// else {
		// 	snprintf(ip_addr_src_ch, sizeof(ip_addr_src_ch), "%s", inet_ntoa(my_ip->ip_src));
		// 	ip_addr_src = ip_addr_src_ch;

		// 	snprintf(ip_addr_dst_ch, sizeof(ip_addr_dst_ch), "%s", inet_ntoa(my_ip->ip_dst));
		// 	ip_addr_dst = ip_addr_dst_ch;

		// 	ttl = my_ip->ip_ttl;
		// }

    
	}

	else if (ip_v.compare("IPv6") == 0) {
		//ipv = "IPv6";
		// size_ip = 40;

		char buffer[INET6_ADDRSTRLEN];

		snprintf(ip_addr_src_ch, sizeof(ip_addr_src_ch), "%s", inet_ntop(AF_INET6, &(my_ip6->ip6_src), buffer, INET6_ADDRSTRLEN));
		ip_addr_src = ip_addr_src_ch;

		snprintf(ip_addr_dst_ch, sizeof(ip_addr_dst_ch), "%s", inet_ntop(AF_INET6, &(my_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN));
		ip_addr_dst = ip_addr_dst_ch;

		hop_limit = my_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	}

	Pac->set_L3_layer(ip_v, ip_addr_src, ip_addr_dst, ttl, hop_limit);

		// for (int i = 0; i < Pac->total_packet_len; i++) {
		// 	printf("packet[%d]: %x\n", i, packet[i]);
		// }

	l4_protocol(ip_v, packet, Pac);	
	
}


bool sortByBytes(const Packet &p1, const Packet &p2) {
	return p1.len > p2.len;
}

bool sortByBytes_a(const AggregatedPackets &p1, const AggregatedPackets &p2) {
	return p1.size > p2.size;
}

bool sortByPackets(const AggregatedPackets &p1, const AggregatedPackets &p2) {
	return p1.num > p2.num;
}

// void aggregation_output(vector<Packet> *packets, vector<AggregatedPackets> *aggr_packets, string aggr_key, int size, bool sort_by_packets, bool sort_by_bytes) {
// 		// cout << "mam srcip: " << aggrkey << endl;

// 	if (strcmp(aggr_key, "srcmac") == 0) {
// 		aggr_srcmac = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			aggregate_packet(&aggr_packets, it->src_mac, it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}

// 	else if (strcmp(aggrkey, "dstmac") == 0) {
// 		aggr_dstmac = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			aggregate_packet(&aggr_packets, it->dst_mac, it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}

// 	else if (strcmp(aggrkey, "srcip") == 0) {
// 		aggr_srcip = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			aggregate_packet(&aggr_packets, it->ip_addr_src, it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}

// 	else if (strcmp(aggrkey, "dstip") == 0) {
// 		aggr_dstip = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			aggregate_packet(&aggr_packets, it->ip_addr_dst, it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}

// 	else if (strcmp(aggrkey, "srcport") == 0) {
// 		aggr_srcport = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			if (it->src_port == -1) {
// 				cerr << "File doesn't contain such aggregation key." << endl;
// 				exit(1);
// 			}
// 			aggregate_packet(&aggr_packets, to_string(it->src_port), it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}

// 	else if (strcmp(aggrkey, "dstport") == 0) {
// 		aggr_dstport = true;
// 		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
// 			if (it->dst_port == -1) {
// 				cerr << "File doesn't contain such aggregation key." << endl;
// 				exit(1);
// 			}
// 			aggregate_packet(&aggr_packets, to_string(it->dst_port), it->len);
// 		}
// 		if (sort_by_packets){
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
// 			for (AggregatedPackets &aggrPack : aggr_packets) {
// 				aggrPack.print_aggr();
// 			}
// 		}
// 		else if (sort_by_bytes) {
// 			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
// 			for (AggregatedPackets &aggrPack : aggr_packets){
// 				aggrPack.print_aggr();
// 			}
// 		} 
// 		else {
// 			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
// 				it2->print_aggr();
// 			}
// 		}
// 	}
// 	else {
// 		cerr << "Wrong argument value [-a aggr-key]!" << endl;
// 		exit(1);
// 	}
// }

static string vlan_id("");

void next_header_type(const u_char* packet, Packet *Pac, int offset, vector<FragmentedPacket> *frag_packets) {

	// cout << vlan_id << endl;
	char src_mac_ch[18];
	string src_mac;
	char dst_mac_ch[18];
	string dst_mac;
	string ipv;

	// for(int i = 0; i < pac->len; i++) {
	// 	printf("offset[%d]: %x\n", i, packet[i]);
	// }

	struct ether_header *eptr;
	eptr = (struct ether_header*)(packet+offset);

	snprintf(src_mac_ch, sizeof(src_mac_ch), "%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
	src_mac = src_mac_ch;
	
	snprintf(dst_mac_ch, sizeof(dst_mac_ch), "%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
	dst_mac = dst_mac_ch;

	switch (ntohs(eptr->ether_type)) {
    	case ETHERTYPE_IP:
    		ipv = "IPv4";
	    	l3_protocol(ipv, packet+offset, Pac, frag_packets);
	    	break;

    	case ETHERTYPE_IPV6:
    		ipv = "IPv6";
			l3_protocol(ipv, packet+offset, Pac);
		    break;

		case ETH_P_8021Q: 
			// for(int i = 0; i < 120; i++) {
	  //    			printf("eth %d: %d \n",i, packet[i]);
			// }
	    	vlan_id += to_string(packet[SIZE_ETHERNET+offset+1]) + " ";
	    	next_header_type(packet, Pac, offset+4, frag_packets);
	    	break;

	    case ETH_P_8021AD:
	  //   	cout << "802.1ad" << endl;
		 //    for(int i = 0; i < 120; i++) {
	  //    			printf("eth %d: %x \n",i, packet[i]);
			// }	
	    	vlan_id = to_string(packet[SIZE_ETHERNET+1]) + " ";
			next_header_type(packet, Pac, offset+4, frag_packets);
			break;

		default:
			Pac->is_unsupported = true;
			// cerr << "Unknown EtherType value!" << endl;
			// exit(1);
			break;
	}
//void Packet::set_L2_layer(string smac, string dmac, string vlanid) {
	// cout << vlan_id_final << endl;
	Pac->set_L2_layer(src_mac, dst_mac, vlan_id);
}



int main(int argc, char **argv) {

  	char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
  	const u_char *packet;
  	struct ip *my_ip;
  	struct ip *my_vlan_ip;
	const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
  	const struct udphdr *my_udp;    // pointer to the beginning of UDP header
  	struct icmphdr *my_icmp, *my_vlan_icmp; 
  	struct pcap_pkthdr header;  
  	struct ether_header *eptr;
  	pcap_t *handle;                 // file/device handler
  	u_int size_ip;
  	struct ip6_hdr *my_ip6, *my_vlan_ip6;
  	// struct vlan_ethhdr *my_vlan;
  	// struct vlan_dev_priv *vlan_priv;
  	struct ethhdr* my_eth;
  	// map<int,int> my_map;

  	struct bpf_program fp;
	bpf_u_int32 netaddr = 0;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
	char *dev = NULL;

	///Arguments Parsing
	const char* aggrkey;
	const char* filter_expr = "";
	const char* sort_key;
	int limit;
	
	//bool variables
	bool input_files = false;
	bool sort_by_packets = false;
	bool sort_by_bytes = false;
	bool aggr_srcmac = false;
	bool aggr_dstmac = false;
	bool aggr_srcip = false;
	bool aggr_dstip = false;
	bool aggr_srcport = false;
	bool aggr_dstport = false;
	bool is_limited = false;
	bool filter = false;
	bool vlan1q = false;
	bool vlan1ad = false;
	bool fragmentation = false;

	///counter variables
	int p = 0;
	int n = 0;
	int counter;


	vector<Packet> packets;
	vector<AggregatedPackets> aggr_packets;
	vector<FragmentedPacket> frag_packets;
	//sorting variables

	string aggrKey;

	if (argc == 2) {
		if (strcmp("-h", argv[1]) == 0) {
			cout << "Usage: isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] files ..." << endl;
			exit(0);
		}
	}

	int c;
	while ((c = getopt (argc, argv, "a:s:l:f:")) != -1) {
		switch(c) {
			case 'a':
			if (optarg) {
				aggrkey = optarg;
					// aggr_key = true;
				// cout << "aggrkey: " << aggrkey << endl;

				if (strcmp(aggrkey, "srcmac") == 0) {
					aggr_srcmac = true;
				}

				else if (strcmp(aggrkey, "dstmac") == 0) {
					aggr_dstmac = true;
				}

				else if (strcmp(aggrkey, "srcip") == 0) {
					aggr_srcip = true;
				}

				else if (strcmp(aggrkey, "dstip") == 0) {
					aggr_dstip = true;
				}

				else if (strcmp(aggrkey, "srcport") == 0) {
					aggr_srcport = true;
				}

				else if (strcmp(aggrkey, "dstport") == 0) {
					aggr_dstport = true;
				}
				else {
					cerr << "Wrong argument value [-a aggr-key]!" << endl;
					exit(1);
				}

				break;
			}

			case 's':
			if (optarg) {
				sort_key = optarg;
				// cout << "sort key:" << sort_key << endl;
				if (strcmp(sort_key, "packets") == 0) {
					sort_by_packets = true;
				}
				else if (strcmp(sort_key, "bytes") == 0) {
					sort_by_bytes = true;
				}
				else {
					cerr << "Wrong argument value [-s sort-key]!" << endl;
					exit(1);
				}
				break;
			}

			case 'l':
			if (optarg) {
				//cout << optarg << endl;
				limit = atoi(optarg);
				//cout << limit << endl;
				is_limited = true;
				// cout << "limit: " << limit << endl;
				if (limit < 0) {
					cerr << "Wrong argument value [-l limit]!" << endl;
					exit(1);
				}

				break;
			}

			case 'f':
				if (optarg) {
					filter_expr = optarg;
					cout << "filter type, dir, proto: " << filter_expr << endl;
				}
				break;

			default:
				// cout << "default" << endl;
				// if (optarg) {
				// 	cout << optarg << endl;
				// }
				// err(1, "Invalid input arguments!\n");
				cerr << "Invalid input arguments!" << endl;
				exit(1);
				break;
		}

	}

	while (argc > optind) {


		if ((handle = pcap_open_offline(argv[optind],errbuf)) == NULL)
			err(1,"Can't open file %s for reading", argv[optind]);

		if (strcmp(filter_expr, "") != 0) {
			if (pcap_compile(handle,&fp,filter_expr,0,netaddr) == -1)
				err(1,"pcap_compile() failed");

			if (pcap_setfilter(handle,&fp) == -1)
				err(1,"pcap_setfilter() failed");
		}

		while ((packet = pcap_next(handle,&header)) != NULL){

			Packet Pac;
			n++;
			p++;

			long long ts = 100000 * header.ts.tv_sec + header.ts.tv_usec;

			Pac.set_values(p, ts, header.len);
			cout << endl;
			cout << p << "." << endl;
			next_header_type(packet, &Pac, 0, &frag_packets);
			if (!frag_packets.empty()) {
				fragmentation = true;
			}
			    	
			packets.push_back(Pac);

		}

		pcap_close(handle);
		optind++;
	}


	if (aggr_srcip) {
		counter = 1;
		// cout << "mam srcip: " << aggrkey << endl;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			aggregate_packet(&aggr_packets, it->ip_addr_src, it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}
	}

	else if (aggr_dstip) {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			aggregate_packet(&aggr_packets, it->ip_addr_dst, it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}
	}

	else if (aggr_srcmac) {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			aggregate_packet(&aggr_packets, it->src_mac, it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}

	}

	else if (aggr_dstmac) {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			aggregate_packet(&aggr_packets, it->dst_mac, it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}
	}

	else if (aggr_srcport) {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			if (it->src_port == -1) {
				cerr << "File doesn't contain such aggregation key." << endl;
				exit(1);
			}
			aggregate_packet(&aggr_packets, to_string(it->src_port), it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}
	}

	else if (aggr_dstport) {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			if (it->dst_port == -1) {
				cerr << "File doesn't contain such aggregation key." << endl;
				exit(1);
			}
			aggregate_packet(&aggr_packets, to_string(it->dst_port), it->len);
		}
		if (sort_by_packets){
			sort(aggr_packets.begin(), aggr_packets.end(), sortByPackets);
			for (AggregatedPackets &aggrPack : aggr_packets) {
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		}
		else if (sort_by_bytes) {
			sort(aggr_packets.begin(), aggr_packets.end(), sortByBytes_a);
			for (AggregatedPackets &aggrPack : aggr_packets){
				aggrPack.print_aggr(limit, is_limited, counter++);
			}
		} 
		else {
			for (vector<AggregatedPackets>::iterator it2 = aggr_packets.begin(); it2 != aggr_packets.end(); ++it2) {
				it2->print_aggr(limit, is_limited, counter++);
			}
		}

	}
	else if (sort_by_bytes) {
		counter = 1;
		sort(packets.begin(), packets.end(), sortByBytes);
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			if ((is_limited) && (counter > limit)) {
				break;
			}
			it->output();
			counter++;
		}
		// for (Packet &pack : packets){
		// 	pack.output();
		// }
	}
	else {
		counter = 1;
		for (vector<Packet>::iterator it = packets.begin(); it != packets.end(); ++it) {
			
			if (fragmentation) {

				if (it->is_reassembled) { 
					it->num = counter;
					if ((is_limited) && (counter > limit)) {
						break;
					}
					it->output();
					counter++;
				}
			}
			else {
				if ((is_limited) && (it->num > limit)) {
					break;
				}
				it->output();
			}
			// it->output();
		    // cout << it->num << ": " << it->ts << " " << it->len << " | " << "Ethernet: " << it->src_mac << " " << it->dst_mac << " " << it->vlan_id << "| " << it->ipv << ": " << it->ip_addr_src << " " << it->ip_addr_dst << " ";				// for (int k = 1; k < my_map.size()+1; k++) {
		    // it->ttlOrHop();
		    // cout << " | ";
		    // it->l4_output();
		}
	}
	return 0;
}