#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <linux/if_ether.h>
#include <err.h>
#include <iostream>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sstream>
#include <linux/icmp.h>
#include <getopt.h>
#include <linux/if_vlan.h>
#include <pcap/vlan.h>
//#include <uapi/linux/if_vlan.h>

#include <iomanip>


#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
// #include <uapi/linux/if_vlan.h>
#endif

using namespace std;

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

//#define HEX(x) setw(2) << setfill('0') << hex << (int)( x )

void icmp(int version, const u_char *packet) {
	// bool is_vlan as 4th param?
	int type;
	int code;
	//struct icmphdr *my_vlan_icmp;
	//my_vlan_icmp = (struct icmphdr*)(packet);
	//for (int i = 0; i < 120 ; i++) {
	// 	// my_vlan_icmp = (struct icmphdr*)(packet+i);
	// 	// cout << ntohs(my_vlan_icmp->type) << " " << ntohs(my_vlan_icmp->code) << endl;
	// 	printf("eth %d: %d \n",i, packet[i]);
	// }

	cout << "ICMPv" << version << ": ";
	if (version == 6) {
		type = (int)packet[54];
		code = (int)packet[55];
		cout << type << " " << code << " ";	

		if (type == 1){
			cout << "destinaton unreachable ";
			switch(code) {
				case 0:
					cout << "no route destination" << endl;
					break;

				case 1:
					cout << "communication with destination administratively prohibited" << endl;
					break;

				case 2:
					cout << "beyond scope of source address" << endl;
					break;

				case 3:
					cout << "address unreachable" << endl;
					break;

				case 4:
					cout << "port unreachable" << endl;
					break;

				case 5:
					cout << "source address failed ingress/engress policy" << endl;
					break;

				case 6:
					cout << "reject route to destination" << endl;
					break;
			}
		}

		else if (type == 2) {
			cout << "packet too big" << endl;
			 
		}

		else if (type == 3) {
			cout << "time exceeded ";
			if (code == 0) {
				cout << "hop limit exceeded in transit" << endl;
			}

			else if (code == 1) {
				cout << "fragment reassembly time exceeded" << endl;
			}
		}

		else if (type == 4) {
			cout << "parameter problem ";
			switch(code) {
				case 0:
					cout << "rrroneous header field encountered" << endl;
					break;

				case 1:
					cout << "unrecognized Next Header type encountered" << endl;
					break;

				case 2:
					cout << "urecognized IPv6 option encountered" << endl;
					break;
			}
		}

		else if ((type == 100) || (type == 101) || (type == 200) || (type == 201)) {
			cout << "private experimentation ";
		}
	}
	else if (version == 4) {
		type = (int)packet[42];
		code = (int)packet[43];
		cout << type << " " << code << " ";	

		if (type == 0) {
			cout << "echo message" << endl;
		}

		else if (type == 3) {
			switch(code) {
				case 0:
					cout << "net unreachable" << endl;
					break;

				case 1:
					cout << "host unreachable" << endl;
					break;

				case 2:
					cout << "protocol unreachable" << endl;
					break;

				case 3:
					cout << "port unreachable" << endl;
					break;

				case 4:
					cout << "fragmentation needed and DF set" << endl;
					break;

				case 5:
					cout << "source route failed" << endl;
					break;
			}
		}
		else if (type == 5) {
			switch(code) {
				case 0:
					cout << "redirect datagrams for the Network" << endl;
					break;

				case 1:
					cout << "redirect datagrams for the Host" << endl;
					break;

				case 2:
					cout << "redirect datagrams for the Type of Service and Network" << endl;
					break;

				case 3:
					cout << "redirect datagrams for the Type of Service and Host" << endl;
					break;
			}
		}
		else if (type == 8) {
			cout << "echo reply message" << endl;
		}

		else if (type == 11) {
			if (code == 0) {
				cout << "time to live exceeded in transit" << endl;
			}
			else if (code == 1) {
				cout << "fragment reassembly time exceeded" << endl;
			}
		}
		else if (type == 12) {
			// cout << "parameter problem ";
			if (code == 0) {
				cout << "pointer indicates error" << endl;
			}
		} 
		else if (type == 13) {
			cout << "timestamp message" << endl;
		}
		else if (type == 14) {
			cout << "timestamp reply message" << endl;
		}
		else if (type == 15) {
			cout << "information request message" << endl;
		} 
		else if (type == 16) {
			cout <<  "information reply message" << endl;
		}		
	}
}


void ipv4_protocol(struct ip *my_ip, const u_char *packet, u_int size_ip) {
	//bool is_vlan as 4th param?
	const struct tcphdr *my_tcp;
	const struct udphdr *my_udp;
	//VLAN????
	// const struct tcphdr *my_vlan_tcp;
	// const struct udphdr *my_vlan_udp;

	switch (my_ip->ip_p) {
		case 6:
			cout << "TCP: ";
			my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
			cout << ntohs(my_tcp->th_sport) << " " << ntohs(my_tcp->th_dport) << " " << my_tcp->th_seq << " " << my_tcp->th_ack << " ";

				if (my_tcp->th_flags & TH_CWR){
					cout << "C";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_ECE){
					cout << "E";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_URG){
					cout << "U";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_ACK){
					cout << "A";	
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_PUSH){
					cout << "P";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_RST){
					cout << "R";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_SYN){
					cout << "S";
				}
				else{
					cout << ".";
				}
				if (my_tcp->th_flags & TH_FIN){
					cout << "F";
				}
				else{
					cout << ".";
				}
				cout << endl;

				break;

		case 17:
			cout << "UDP: ";
			my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
			cout << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
			break;

		default:
			icmp(4, packet);
			break;
	}
}

// void format_mac_addr(unsigned char *mac_addr) {
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[0];
// 	cout << ":";
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[1];
// 	cout << ":";
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[2];
// 	cout << ":";
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[3];
// 	cout << ":";
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[4];
// 	cout << ":";
// 	cout << setfill('0') << setw(2) << hex << (int)mac_addr[5];
// }


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

	///counter variables
	int p = 0;
	int n = 0;

	// string files;

	if (argc == 2) {
		if (strcmp("-h", argv[1]) == 0) {
			cout << "Usage: isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ..." << endl;
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
				cout << "aggrkey: " << aggrkey << endl;

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
				cout << "sort key:" << sort_key << endl;
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
				cout << "limit: " << limit << endl;
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
				cout << "default" << endl;
				if (optarg) {
					cout << optarg << endl;
				}
				break;
				// err(1, "Invalid input arguments!\n");
				// cerr << "Invalid input arguments!" << endl;
				// exit(1);
		}

	}
	// if (c == -1) {
	// 	// cout << "argc:" << argc << endl;
	// 	// cout << "optind:" << optind << endl;
	// 	cout << argv[optind] << endl;
	// 	// exit(0);
	// }

	// dev = pcap_lookupdev(errbuf);
	// if (dev == NULL) {
	// 		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
	// 		exit(EXIT_FAILURE);
	// }


	// int numOfArgs = argc - 1;
	while (argc > optind) {
		// if (strcmp(argv[numOfArgs], "file") == 0) {
			// input_files = true;
			// while (numOfArgs < argc-1) {

		if ((handle = pcap_open_offline(argv[optind],errbuf)) == NULL)
			err(1,"Can't open file %s for reading", argv[optind]);

		// printf("Opening file %s for reading ...\n\n", argv[optind]);

  		// 		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
				// 	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
				// 	netaddr = 0;
				// 	mask = 0;
				// }

		if (strcmp(filter_expr, "") != 0) {
			if (pcap_compile(handle,&fp,filter_expr,0,netaddr) == -1)
				err(1,"pcap_compile() failed");

			if (pcap_setfilter(handle,&fp) == -1)
				err(1,"pcap_setfilter() failed");
		}

  				// read packets from the file
		while ((packet = pcap_next(handle,&header)) != NULL){
			n++;
			p++;

			if ((is_limited) && (n > limit)) {
				break;
			}

			long long ts = 100000 * header.ts.tv_sec + header.ts.tv_usec;
				    // unsigned short int hdr_len = ntohs(my_ip->ip_len);
				    // unsigned int total_len = hdr_len + my_ip->ip_hl*4 - 6;
				    // cout << total_len << endl;
				    //ntohs(my_ip->ip_len) + ntohs(my_ip->ip_id) - 6

				    //my_ip6_2 = (struct ip6_hdr*) (packet+SIZE_ETHERNET+20);
			eptr = (struct ether_header *) packet;

			my_ip = (struct ip*)(packet+SIZE_ETHERNET);        // skip Ethernet header

			my_ip6 = (struct ip6_hdr*)(packet+SIZE_ETHERNET);

				    // my_icmp = (struct icmphdr*)(packet+SIZE_ETHERNET);

				    // my_vlan = (struct vlan_ethhdr*)(packet + SIZE_ETHERNET);

				    // vlan_priv = (struct vlan_dev_priv*)(packet + SIZE_ETHERNET); 


				    //DID:
				    //total size of packet IPv4, IPv6 ------ SOLVED!!!
				    //VLAN - 802.1q, 802.1ad ------ SOLVED!!!
				    //flags (CWR, ECE) by TCP, unknown offsets for flags ------ SOLVED!!!
				    //limit issue ------ SOLVED!!!
				   	//ICMPv4, ICMPv6 - type and code ??? ----- PARTIAL SOLVED ???!!!
				   	//MAC Address first 0 ------ SOLVED!!!
				   	//filter expr ------ SOLVED!!!
					//VLAN IPv4 size_ip ----- SOLVED!!!
					//TODO
					//sort
				   	//agregation
				   	//fragmentation
				    
				    switch (ntohs(eptr->ether_type)) {
				    	case ETHERTYPE_IP:

					    	size_ip = my_ip->ip_hl*4;

					    	cout << to_string(p) + ": " + to_string(ts) + " " << setprecision(2) << header.len << " | ";

					    	cout << "Ethernet: ";
					  //   	format_mac_addr(eptr->ether_shost);
							// cout << " ";
							// format_mac_addr(eptr->ether_dhost);
							cout << " | ";
					    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
				    		cout << " ";
					    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
					    	cout << " | ";
					    	// cout << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " | ";

					    	cout << "IPv4: " << inet_ntoa(my_ip->ip_src) << " " << inet_ntoa(my_ip->ip_dst) << " " << to_string(my_ip->ip_ttl) << " | ";

					    	ipv4_protocol(my_ip, packet, size_ip);

					    	break;


				    	case ETHERTYPE_IPV6:
					    	size_ip = 40;
					    	cout << to_string(p) + ": " + to_string(ts) + " " << setprecision(2) << header.len << " | ";
					    	// cout << setprecision(2) << header.len << " | ";
					    	//cout << "Ethernet: " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " | ";
					    	cout << "Ethernet: ";
					  //   	format_mac_addr(eptr->ether_shost);
							// cout << " ";
							// format_mac_addr(eptr->ether_dhost);
							// cout << " | ";
					    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
				    		cout << " ";
					    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
					    	cout << " | ";


					    	char buffer[INET6_ADDRSTRLEN];
					    	cout << "IPv6: " << inet_ntop(AF_INET6, &(my_ip6->ip6_src), buffer, INET6_ADDRSTRLEN) << " " << inet_ntop(AF_INET6, &(my_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN) << " " << to_string(my_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)  << " | ";

					    	switch (my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt){
					    		case 17:
						    		my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
						    		cout << "UDP: " << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
						    		break;

						    	default:
						    		icmp(6, packet);
						    		break;
						    }
						    break;

				   

					    default:
				   //   		for(int i = 0; i < 120; i++) {
				   //  			printf("eth %d: %d \n",i, packet[i]);
							// 	//cout << HEX(packet[i]) << endl;
							// }
					    	my_vlan_ip = (struct ip*)(packet+22);
					    	size_ip = my_vlan_ip->ip_hl*4;
					    	my_vlan_ip6 = (struct ip6_hdr*)(packet+18);

					    	if ((packet[12] == 0x81) && (packet[13] == 0x00)) {
								vlan1q = true;//802.1q
								cout << to_string(p) + ": " + to_string(ts) + " " << setprecision(2) << header.len << " | ";
								cout << "Ethernet: ";
						    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
					    		cout << " ";
						    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
						    	cout << " | ";
								 //<< " " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " " <<  to_string(packet[15]) << " | ";
								// cout << "old:" << endl;
								// cout << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " " <<  to_string(packet[15]) << " | ";

							}
							else if ((packet[12] == 0x88) && (packet[13] == 0xa8) && (packet[16] == 0x81) && (packet[17] == 0x00)) {
								vlan1ad = true;//802.1ad
								cout << to_string(p) + ": " + to_string(ts) + " " << setprecision(2) << header.len << " | ";
								cout << "Ethernet: ";
						    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5]);
					    		cout << " ";
						    	printf("%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
						    	cout << " | ";
								// cout << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << setfill('0') << setw(17) << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " " <<  to_string(packet[15]) << " " << to_string(packet[19]) << " | ";
							}
							else {
								cerr << "Unknown EtherType value!" << endl;
								exit(1);
							}

							if (vlan1q) {
								if ((packet[16] == 0x86) && (packet[17] == 0xdd)) {
									cout << "IPv6: ";
									cout << inet_ntop(AF_INET6, &(my_vlan_ip6->ip6_src), buffer, INET6_ADDRSTRLEN) << " " << inet_ntop(AF_INET6, &(my_vlan_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN) << " " << to_string(my_vlan_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)  << " | ";

									if (my_vlan_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17){
							    		my_udp = (struct udphdr *)(packet+58); // pointer to the UDP header
							    		cout << "UDP: " << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;	
							    	}
							    	else {
							    		icmp(6, packet);
							    	}

							    }
							    else if ((packet[16] == 0x08) && (packet[17] == 0x00)){
							    	cout << "IPv4: ";
							    	cout << inet_ntoa(my_vlan_ip->ip_src) << " " << inet_ntoa(my_vlan_ip->ip_dst) << " " << to_string(my_vlan_ip->ip_ttl) << " | ";
							    	ipv4_protocol(my_vlan_ip, packet, size_ip);
							    }
							}
							else if (vlan1ad) {
								if ((packet[20] == 0x86) && (packet[21] == 0xdd)){
									cout << "IPv6: ";
									cout << inet_ntop(AF_INET6, &(my_vlan_ip6->ip6_src), buffer, INET6_ADDRSTRLEN) << " " << inet_ntop(AF_INET6, &(my_vlan_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN) << " " << to_string(my_vlan_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)  << " | ";				    				
									if (my_vlan_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17){
							    		my_udp = (struct udphdr *)(packet+58); // pointer to the UDP header
							    		cout << "UDP: " << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;	
							    	}
							    	else {
							    		icmp(6, packet);
							    	}
							    } 
							    else if ((packet[20] == 0x08) && (packet[21] == 0x00)) {
							    	cout << "IPv4: ";
							    	cout << inet_ntoa(my_vlan_ip->ip_src) << " " << inet_ntoa(my_vlan_ip->ip_dst) << " " << to_string(my_vlan_ip->ip_ttl) << " | ";
							    	ipv4_protocol(my_vlan_ip, packet, size_ip);
							    }
							}
							break;
						}
						cout << endl;
					}
					// printf("End of file reached ...\n");

				// close the capture device and deallocate resources
					pcap_close(handle);
					optind++;
				}
				return 0;
			}