#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h> 
#include <arpa/inet.h>
#include <err.h>
#include <iostream>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sstream>
#include <getopt.h>
#include <iomanip>
#include <map>
#include <list>
#include <iterator>
#include <algorithm>
#include <vector>

#ifdef __linux__      
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#include <linux/if_ether.h>
#endif

#include "isashark.h"

using namespace std;

void AggregatedPackets::print_aggr(int limit, bool is_limited, int counter) {
	if (this->aggrkey.compare("-1") == 0) {
		return;
	}

	if ((is_limited) && (counter > limit)) {
		return;
	}
	cout << this->aggrkey << ": " << this->num << " " << this->size << endl;
}

void aggregate_packet(vector<AggregatedPackets> *aggr_pac, string aggr_key, int len){
	bool record_exists = false;

	if(aggr_pac->empty()) {
		AggregatedPackets Pac;
		Pac.aggrkey = aggr_key;
		Pac.num++;
		Pac.size = len;
		aggr_pac->push_back(Pac);
	}
	else {
		for (vector<AggregatedPackets>::iterator it = aggr_pac->begin(); it != aggr_pac->end(); ++it) {
			if (it->aggrkey.compare(aggr_key) == 0) {
				it->num++;
				it->size += len;
				record_exists = true;
			}
		}

		if (!record_exists) {
			AggregatedPackets Pac;
			Pac.aggrkey = aggr_key;
			Pac.num++;
			Pac.size = len;
			aggr_pac->push_back(Pac);
		}
	}
}


void Packet::set_values(int packet_num, long long time_stamp, int length) {
	num = packet_num;
	ts = time_stamp;
	len = length;
}

void Packet::set_L2_layer(string smac, string dmac) {
	src_mac = smac;
	dst_mac = dmac;
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
	}

	if (this->seq_num != -1) {
		cout << " ";
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
			type_description = "destination unreachable";
			switch(code) {
				case 0:
					code_description = "no route to destination";
					break;

				case 1:
					code_description = "communication with destination administratively prohibited";
					break;

				case 2:
					code_description = "beyond scope of source address";
					break;

				case 3:
					code_description = "address unreachable";
					break;

				case 4:
					code_description = "port unreachable";
					break;

				case 5:
					code_description = "source address failed ingress/engress policy";
					break;

				case 6:
					code_description = "reject route to destination";
					break;

				case 7:
					code_description = "error in source routing header";
					break;
			}
		}

		else if (type == 2) {
			type_description = "packet too big";
		}

		else if (type == 3) {
			type_description = "Time exceeded";
			if (code == 0) {
				code_description = "hop limit exceeded in transit";
			}

			else if (code == 1) {
				code_description = "fragment reassembly time exceeded";
			}
		}

		else if (type == 4) {
			type_description = "Parameter problem";
			switch(code) {
				case 0:
					code_description = "erroneous header field encountered";
					break;

				case 1:
					code_description = "unrecognized Next Header type encountered";
					break;

				case 2:
					code_description = "unrecognized IPv6 option encountered";
					break;
			}
		}

		else if ((type == 100) || (type == 101) || (type == 200) || (type == 201)) {
			type_description = "private experimentation";
		}

		else if (type == 128) {
			type_description = "echo Request";
		}

		else if (type == 129) {
			type_description = "echo Reply";
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
			type_description = "echo reply";
		}

		else if (type == 3) {
			type_description = "destination unreachable";
			switch(code) {
				case 0:
					code_description = "net unreachable";
					break;

				case 1:
					code_description = "host unreachable";
					break;

				case 2:
					code_description = "protocol unreachable";
					break;

				case 3:
					code_description = "port unreachable";
					break;

				case 4:
					code_description = "fragmentation needed and DF set";
					break;

				case 5:
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
		else if (type == 4) {
			type_description = "source quench";
		}
		else if (type == 5) {
			type_description = "redirect";
			switch(code) {
				case 0:
					code_description = "redirect datagrams for the Network";
					break;

				case 1:
					code_description = "redirect datagrams for the Host";
					break;

				case 2:
					code_description = "redirect datagrams for the Type of Service and Network";
					break;

				case 3:
					code_description = "redirect datagrams for the Type of Service and Host";
					break;
			}
		}
		else if (type == 8) {
			type_description = "echo";
		}

		else if (type == 9) {
			type_description = "router advertisment";
		}

		else if (type == 10) {
			type_description = "router solicitation";
		}

		else if (type == 11) {
			type_description = "time exceeded";
			if (code == 0) {
				code_description = "time to live exceeded in transit";
			}
			else if (code == 1) {
				code_description = "fragment reassembly time exceeded";
			}
		}
		else if (type == 12) {
			type_description = "parameter problem";
			if (code == 0) {
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
			type_description = "timestamp";
		}
		else if (type == 14) {
			type_description = "timestamp reply";
		}
		else if (type == 15) {
			type_description = "information request";
		} 
		else if (type == 16) {
			type_description = "information reply";
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

void extended_IPv6_header(uint8_t next, const u_char* packet, Packet *Pac) {

	struct ip6_ext *my_ip6_ext;
	int total_offset = 0;
	bool extended_hdr = false;
	my_ip6_ext = (struct ip6_ext*)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR);
	
	while (total_offset < Pac->len) {
		if ((my_ip6_ext->ip6e_nxt == 6) || (my_ip6_ext->ip6e_nxt == 17) || (my_ip6_ext->ip6e_nxt == 58)) {
			
			extended_hdr = true;
			l4_protocol("IPv6", packet, Pac, total_offset+34, extended_hdr);
			break;
		} 
		else {
			total_offset += 8*(1+(int)my_ip6_ext->ip6e_len);
			my_ip6_ext = (struct ip6_ext*)(packet+SIZE_ETHERNET+SIZE_IPV6_HDR+total_offset);
		}
	}	
	
	if (!extended_hdr) {
		Pac->is_unsupported = true;
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

	if (ipv.compare("IPv4") == 0) {

		switch (my_ip->ip_p) {
			case 1:
				icmp(4, packet, Pac);
				break;
				
			case 6:
				l4_id = "TCP: ";
				if (Pac->is_reassembled) {
					
					my_tcp = (struct tcphdr *)(Pac->data_buffer);
				}
				else {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+SIZE_IP_HDR); // pointer to the TCP header
				}
				
				src_port = ntohs(my_tcp->th_sport);
				dst_port = ntohs(my_tcp->th_dport);
				
				seq_num = htonl(my_tcp->th_seq);
				ack_byte = htonl(my_tcp->th_ack);

				if (my_tcp->th_flags & TH_CWR){
					flags = flags + "C";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ECE){
					flags = flags + "E";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_URG){
					flags = flags + "U";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ACK){
					flags = flags + "A";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_PUSH){
					flags = flags + "P";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_RST){
					flags = flags + "R";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_SYN){
					flags = flags + "S";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_FIN){
					flags = flags + "F";
				}
				else{
					flags = flags + ".";
				}

				break;

				case 17:
					l4_id = "UDP: ";
					if (Pac->is_reassembled) {
						
						my_udp = (struct udphdr *)(Pac->data_buffer);
					}
					else {
						my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+SIZE_IP_HDR); // pointer to the UDP header
					}
					src_port = ntohs(my_udp->uh_sport);
					dst_port = ntohs(my_udp->uh_dport);
					break;

				default:
					Pac->is_unsupported = true;
					
					break;
			}
	}

	else if (ipv.compare("IPv6") == 0) {
		uint8_t next_hdr = my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		switch (my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
			case 6:
				
				l4_id = "TCP: ";
				if (extended_hdr) {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+offset+14); // pointer to the TCP header
				}
				else {
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+SIZE_IPV6_HDR); // pointer to the TCP header
				}
				src_port = ntohs(my_tcp->th_sport);
				dst_port = ntohs(my_tcp->th_dport);
				seq_num = htonl(my_tcp->th_seq);
				ack_byte = htonl(my_tcp->th_ack);

				if (my_tcp->th_flags & TH_CWR){
					flags = flags + "C";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ECE){
					flags = flags + "E";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_URG){
					flags = flags + "U";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_ACK){
					flags = flags + "A";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_PUSH){
					flags = flags + "P";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_RST){
					flags = flags + "R";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_SYN){
					flags = flags + "S";
				}
				else{
					flags = flags + ".";
				}
				if (my_tcp->th_flags & TH_FIN){
					flags = flags + "F";
				}
				else{
					flags = flags + ".";
				}
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
	    		l4_id = "UDP: ";
	    		src_port = ntohs(my_udp->uh_sport);
	    		dst_port = ntohs(my_udp->uh_dport);
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
	    		break;
    	}
	}

	if ((!extended_hdr) && (src_port != -1)) {
		Pac->set_L4_layer(l4_id, src_port, dst_port, seq_num, ack_byte, flags);
	}

}

void FragmentedPacket::create_fragmented_packet(unsigned short id_field, string srcip, string dstip, uint8_t prtcl) {
 	id = id_field;
 	ip_addr_src = srcip;
 	ip_addr_dst = dstip;
 	protocol = prtcl;
}

static int packet_id = 0;


void array_to_array(char *dst, char *src, int len) {
	for (int i = 0; i < len; i++) {
		dst[i] = src[i];
	}
}

void FragmentedPacket::save_data(int offset, char *data, int data_len) {
	for(int x = 0; x < data_len; x++) {
		this->data_buffer[x+offset] = data[x];
	}
}


void hole_filler(FragmentedPacket *FPac, unsigned int total_data_len, unsigned int fragment_offset, char *data, bool flag_mf) {
	for(vector<Hole_Descriptor>::iterator i = FPac->hole_descriptor_list.begin(); i != FPac->hole_descriptor_list.end(); ++i) {

		if (!i->actual) {
			continue;
		}
		if (!flag_mf) {
			FPac->expected_packet_len = fragment_offset+total_data_len;		
		}
		
		if ((i->hole_first > fragment_offset) || (i->hole_last < fragment_offset+total_data_len-1)) {
			continue;
		}
		else if (i->hole_first < fragment_offset) {
			i->actual = false;
			Hole_Descriptor NewHole;
			NewHole.hole_first = i->hole_first;
			NewHole.hole_last = fragment_offset-1;

			if (i->hole_last > fragment_offset+total_data_len-1) {
				Hole_Descriptor NewHole2;
				NewHole2.hole_first = fragment_offset+total_data_len;
				NewHole2.hole_last = i->hole_last;
				
				FPac->hole_descriptor_list.push_back(NewHole2);
			}
			
			FPac->hole_descriptor_list.push_back(NewHole);
			FPac->total_packet_len += total_data_len;
			FPac->save_data(fragment_offset, data, total_data_len);
			
			break;
		}

		else if (i->hole_first == fragment_offset) {
			if (i->hole_last == fragment_offset+total_data_len-1) {
				i->actual = false;
				FPac->total_packet_len += total_data_len;
				FPac->save_data(fragment_offset, data, total_data_len);
			}
			else {
				i->hole_first = fragment_offset+total_data_len;
				FPac->total_packet_len += total_data_len;
				FPac->save_data(fragment_offset, data, total_data_len);
			}

			break;
		}
		else if (i->hole_last == fragment_offset+total_data_len-1) {
			i->hole_last = fragment_offset-1;
			FPac->total_packet_len += total_data_len;
			FPac->save_data(fragment_offset, data, total_data_len);
			break;
		}
	}
}

void fragmentation_reassembly(Packet *Pac, const u_char *packet, string ip_src, string ip_dst, vector<FragmentedPacket> *frag_packets) {
	struct ip* my_ip;
	my_ip = (struct ip*)(packet+SIZE_ETHERNET);
	unsigned int total_data_len = int(packet[17]) - SIZE_IP_HDR;
	bool exists = false;
	bool fragment_exists = false;
	bool flag_mf = int(packet[20]) & 0x20;
	unsigned int fragment_offset = int(packet[21]) << 3;
	char data[total_data_len];

	for (int x = 0; x < total_data_len; ++x) {
		data[x] = packet[Pac->len-total_data_len+x];
	}

	if(frag_packets->empty()) {
		
		FragmentedPacket FPac;
		FPac.packet_id = packet_id++;
		FPac.create_fragmented_packet(my_ip->ip_id, ip_src, ip_dst, my_ip->ip_p);
		FPac.fragment_offset = fragment_offset;
		Hole_Descriptor Hole;
		FPac.hole_descriptor_list.push_back(Hole);
		hole_filler(&FPac, total_data_len, fragment_offset, data, flag_mf);
		frag_packets->push_back(FPac);

	}
	else {
		for (vector<FragmentedPacket>::iterator it = frag_packets->begin(); it != frag_packets->end(); ++it) {
			
			if ((it->id == my_ip->ip_id) && (it->ip_addr_src.compare(ip_src) == 0) && (it->ip_addr_dst.compare(ip_dst) == 0) && (it->protocol == my_ip->ip_p)) {
				exists = true;
				hole_filler(&(*it), total_data_len, fragment_offset, data, flag_mf);
				if (it->expected_packet_len == it->total_packet_len) {
					Pac->is_reassembled = true;
					Pac->total_packet_len = it->total_packet_len;
					Pac->data_buffer = new char[it->total_packet_len];
					array_to_array(Pac->data_buffer, it->data_buffer, it->total_packet_len);
					break;
				}		
				break;
			}
		}
		if ((!exists) && (!Pac->is_reassembled)) {
			FragmentedPacket FPac;
			FPac.packet_id = packet_id++;
			FPac.create_fragmented_packet(my_ip->ip_id, ip_src, ip_dst, my_ip->ip_p);
			FPac.fragment_offset = fragment_offset;
			Hole_Descriptor Hole;
			FPac.hole_descriptor_list.push_back(Hole);
			hole_filler(&FPac, total_data_len, fragment_offset, data, flag_mf);
			
			frag_packets->push_back(FPac);	
		}
	}
}

void l3_protocol(string ip_v, const u_char *packet, Packet *Pac, vector<FragmentedPacket> *frag_packets = 0) {

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
	unsigned int fragment_offset = int(packet[21]) << 3;

	my_ip6 = (struct ip6_hdr*)(packet+SIZE_ETHERNET);

	if (ip_v.compare("IPv4") == 0) {
		
		snprintf(ip_addr_src_ch, sizeof(ip_addr_src_ch), "%s", inet_ntoa(my_ip->ip_src));
		ip_addr_src = ip_addr_src_ch;

		snprintf(ip_addr_dst_ch, sizeof(ip_addr_dst_ch), "%s", inet_ntoa(my_ip->ip_dst));
		ip_addr_dst = ip_addr_dst_ch;

		ttl = my_ip->ip_ttl;
		
		if ((flag_mf) || (fragment_offset != 0)) {
			fragmentation_reassembly(Pac, packet, ip_addr_src, ip_addr_dst, frag_packets);
		}
	}

	else if (ip_v.compare("IPv6") == 0) {

		char buffer[INET6_ADDRSTRLEN];

		snprintf(ip_addr_src_ch, sizeof(ip_addr_src_ch), "%s", inet_ntop(AF_INET6, &(my_ip6->ip6_src), buffer, INET6_ADDRSTRLEN));
		ip_addr_src = ip_addr_src_ch;

		snprintf(ip_addr_dst_ch, sizeof(ip_addr_dst_ch), "%s", inet_ntop(AF_INET6, &(my_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN));
		ip_addr_dst = ip_addr_dst_ch;

		hop_limit = my_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	}

	Pac->set_L3_layer(ip_v, ip_addr_src, ip_addr_dst, ttl, hop_limit);

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

void next_header_type(const u_char* packet, Packet *Pac, int offset, vector<FragmentedPacket> *frag_packets) {

	char src_mac_ch[18];
	string src_mac;
	char dst_mac_ch[18];
	string dst_mac;
	string ipv;

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

	    	Pac->vlan_id += to_string(packet[SIZE_ETHERNET+offset+1]) + " ";
	    	next_header_type(packet, Pac, offset+4, frag_packets);
	    	break;

	    case ETH_P_8021AD:

	    	Pac->vlan_id = to_string(packet[SIZE_ETHERNET+1]) + " ";
			next_header_type(packet, Pac, offset+4, frag_packets);
			break;

		default:
			Pac->is_unsupported = true;
	
			break;
	}

	Pac->set_L2_layer(src_mac, dst_mac);
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
  	struct ethhdr* my_eth;
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
				limit = atoi(optarg);
				is_limited = true;
				if (limit < 0) {
					cerr << "Wrong argument value [-l limit]!" << endl;
					exit(1);
				}

				break;
			}

			case 'f':
				if (optarg) {
					filter_expr = optarg;
				}
				break;

			default:
				cerr << "Invalid input arguments!" << endl;
				exit(1);
				break;
		}

	}

	while (argc > optind) {


		if ((handle = pcap_open_offline(argv[optind],errbuf)) == NULL){
			cerr << "Can't open file " << argv[optind] << " for reading!" << endl;
			exit(3);
		}

		if (strcmp(filter_expr, "") != 0) {
			if (pcap_compile(handle,&fp,filter_expr,0,netaddr) == -1){
				cerr << "pcap_compile() failed" << endl;
				exit(2);
			}

			if (pcap_setfilter(handle,&fp) == -1){
				cerr << "pcap_setfilter() failed" << endl;
				exit(2);
			}
		}

		while ((packet = pcap_next(handle,&header)) != NULL){

			Packet Pac;
			n++;
			p++;

			long long ts = 1000000 * header.ts.tv_sec + header.ts.tv_usec;

			Pac.set_values(p, ts, header.len);

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
				cerr << "Packet doesn't contain any value of aggregation key." << endl;
				continue;
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
				cerr << "Packet doesn't contain any value of aggregation key." << endl;
				continue;
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
		}
	}
	return 0;
}