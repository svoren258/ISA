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
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>
#include <iostream>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sstream>
//#include <iomanip>


#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#endif

using namespace std;

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol


int main(int argc, char **argv) {

	///Arguments Parsing///
  	int n;
  	char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
  	const u_char *packet;
  	struct ip *my_ip;
	const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
  	const struct udphdr *my_udp;    // pointer to the beginning of UDP header
  	struct pcap_pkthdr header;  
  	struct ether_header *eptr;
  	pcap_t *handle;                 // file/device handler
  	u_int size_ip;
  	struct ip6_hdr *my_ip6, *my_ip6_2;
	

	unsigned long long timestamp;
	unsigned int packetlen;
	const char* aggrkey;
	bool aggr_key = false;
	int limit;
	bool is_limited = false;
	const char* filter_expr;
	const char* sort_key;


	string files;

	if (argc == 2) {
		if (strcmp("-h", argv[1]) == 0) {
			cout << "HELP" << endl;
			exit(0);
		}
	}


	

	int c;
	while ((c = getopt (argc, argv, "a:s:l:f:")) != -1) {
		switch(c)
		{
			case 'a':
				if (optarg) {
					//srcmac, dstmac
					aggrkey = optarg;
					aggr_key = true;
					cout << aggrkey << endl;
					//srcip, dstip

					//srcport, dstport
					break;
				}
			case 's':
				if (optarg) {
					sort_key = optarg;
					cout << sort_key << endl;
					break;
				}
			case 'l':
				if (optarg) {
					limit = atoi(optarg);
					is_limited = true;
					if (limit < 0) {
						cerr << "Wrong limit value!" << endl;
						exit(1);
					}
					// cout << limit << endl;

					break;
				}
			case 'f':
				if (optarg) {
					filter_expr = optarg;
					break;
				}
			default:
				// err(1, "Invalid input arguments!\n");
				cerr << "Invalid input arguments!" << endl;
				exit(1);
		}

	}

	int numOfArgs = argc - 1;
	while (numOfArgs >= 1) {
		if (strcmp(argv[numOfArgs], "file") == 0) {
			while (numOfArgs < argc-1) {

				if ((handle = pcap_open_offline(argv[numOfArgs+1],errbuf)) == NULL)
    				err(1,"Can't open file %s for reading", argv[numOfArgs+1]);
  
  					printf("Opening file %s for reading ...\n\n", argv[numOfArgs+1]);
  				  	// read packets from the file
				  	while ((packet = pcap_next(handle,&header)) != NULL){
				    n++;

				    if ((is_limited) && (n > limit)) {
				    	break;
				    }
				    
				    long long ts = 100000 * header.ts.tv_sec + header.ts.tv_usec;
				    // unsigned short int hdr_len = ntohs(my_ip->ip_len);
				    // unsigned int total_len = hdr_len + my_ip->ip_hl*4 - 6;
				    // cout << total_len << endl;
				    //ntohs(my_ip->ip_len) + ntohs(my_ip->ip_id) - 6
				    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header

				    my_ip6 = (struct ip6_hdr*) (packet+SIZE_ETHERNET);
				    //my_ip6_2 = (struct ip6_hdr*) (packet+SIZE_ETHERNET+20);
				    eptr = (struct ether_header *) packet;
				    	
				    // print the packet header data
				    // printf("Packet no. %d:\n", n);
				    // printf("\tLength %d, received at %s", header.len, ctime((const time_t*)&header.ts.tv_sec));  


				    //TODO
				    //total size of packet IPv4, IPv6
				    //ethernet type number ()
				    //seq,ack and flags (CWR, ECE) by TCP

				    

				    switch (ntohs(eptr->ether_type)) {
				    	case ETHERTYPE_IP:
				    		size_ip = my_ip->ip_hl*4;

				    		cout << to_string(n) + ": " + to_string(ts) + " " << ntohs(my_ip->ip_len) + size_ip - 6 << " | " << endl;
				    
				    		cout << "Ethernet: " << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " " << " | " << endl;
				    		
				    		cout << "IPv4: " << inet_ntoa(my_ip->ip_src) << " " << inet_ntoa(my_ip->ip_dst) << " " << to_string(my_ip->ip_ttl) << " | " << endl;
				    		break;

				    	case ETHERTYPE_IPV6:
				    		size_ip = 40;
				    		cout << to_string(n) + ": " + to_string(ts) + " " << ntohs(my_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) << " | " << endl;
				    
				    		cout << "Ethernet: " << ether_ntoa((const struct ether_addr *)&eptr->ether_shost) << " " << ether_ntoa((const struct ether_addr *)&eptr->ether_dhost) << " " << " | " << endl;
				    		char buffer[INET6_ADDRSTRLEN];
				    		cout << "IPv6: " << inet_ntop(AF_INET6, &(my_ip6->ip6_src), buffer, INET6_ADDRSTRLEN) << " " << inet_ntop(AF_INET6, &(my_ip6->ip6_dst), buffer, INET6_ADDRSTRLEN) << " " << to_string(my_ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim)  << " | " << endl;
				    		break;
				    }

				    // std::stringstream stream;
				    // stream << "0x0" << std::hex << ntohs(eptr->ether_type);
				    // string hex_ethertype(stream.str());
				    // cout << hex_ethertype << endl; 

					//if ((hex_ethertype.compare("0x8100") == 0) || (hex_ethertype.compare("0x88A8") == 0)) {		    	
				    // 	cout << "IEEE 802.1Q" << endl;
				    // 	cout << "IEE 802.1ad" << endl;
				    // }

				    
				    switch (my_ip->ip_p) {
				    	case 6:
				    		cout << "TCP: ";
				    		my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
				    		cout << ntohs(my_tcp->th_sport) << " " << ntohs(my_tcp->th_dport) << " " << my_tcp->th_seq << " " << my_tcp->th_ack << " FLAGS" << endl;
				    		// cout << to_string(my_tcp->th_flags) << endl;
				   //  		if (my_tcp->th_flags & TH_CWR){
				   //  			cout << "C";
				   //  		}
				   //  		else{
				   //  			cout << ".";
				   //  		}
				   //  		if (my_tcp->th_flags & TH_ECE){
				   //  			cout << "E";
				   //  		}
				   //  		else{
				   //  			cout << ".";
				   //  		}
				   //  		if (my_tcp->th_flags & TH_URG){
				   //  			cout << "U";
				   //  		}
				   //  		else{
				   //  			cout << ".";
				   //  		}
				   //  		if (my_tcp->th_flags & TH_ACK){
					  // 			cout << "A";	
				   //  		}
				   //  		else{
				   //  			cout << ".";
				   //  		}
					  // 		if (my_tcp->th_flags & TH_PUSH){
					  // 			cout << "P";
					  // 		}
					  // 		else{
				   //  			cout << ".";
				   //  		}
					  // 		if (my_tcp->th_flags & TH_RST){
					  // 			cout << "R";
					  // 		}
					  // 		else{
				   //  			cout << ".";
				   //  		}
				   //  		if (my_tcp->th_flags & TH_SYN){
					  // 			cout << "S";
				   //  		}
				   //  		else{
				   //  			cout << ".";
				   //  		}
							// if (my_tcp->th_flags & TH_FIN){
					  // 			cout << "F";
							// }
							// else{
				   //  			cout << ".";
				   //  		}
							
				    		break;

				    	case 17:
				    		cout << "UDP: ";
				    		my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
				    		cout << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
				    		break;
				    }


				    switch (my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt){
				    	case 17:
				    		my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
				    		cout << "UDP: " << ntohs(my_udp->uh_sport) << " " << ntohs(my_udp->uh_dport) << endl;
				    		break;
				    }
				    
				    // read the Ethernet header
				    eptr = (struct ether_header *) packet;
				    printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
				    printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;
				    
				    switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
				    case ETHERTYPE_IP: // IPv4 packet
				      printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
				      my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
				      size_ip = my_ip->ip_hl*4;                           // length of IP header
				      
				      printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
				      printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
				      printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));
				      
				      switch (my_ip->ip_p){
				      case 2: // IGMP protocol
					printf(", protocol IGMP (%d)\n",my_ip->ip_p);
					break;
				      case 6: // TCP protocol
					printf(", protocol TCP (%d)\n",my_ip->ip_p);
					my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
					printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
					if (my_tcp->th_flags & TH_SYN)
					  printf(", SYN");
					if (my_tcp->th_flags & TH_FIN)
					  printf(", FIN");
					if (my_tcp->th_flags & TH_RST)
					  printf(", RST");
					if (my_tcp->th_flags & TH_PUSH)
					  printf(", PUSH");
					if (my_tcp->th_flags & TH_ACK)
					  printf(", ACK");
					printf("\n");
					break;
				      case 17: // UDP protocol
					printf(", protocol UDP (%d)\n",my_ip->ip_p);
					my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
					printf("\tSrc port = %d, dst port = %d, length %d\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
					break;
				      default: 
					printf(", protocol %d\n",my_ip->ip_p);
				      }
				      break;
				    case ETHERTYPE_IPV6:  // IPv6
				      printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
				      break;
				    case ETHERTYPE_ARP:  // ARP
				      printf("\tEthernet type is 0x%x, i.e., ARP packet\n",ntohs(eptr->ether_type));
				      break;
				    default:
				      printf("\tEthernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
				    } 
				  
				}
				  printf("End of file reached ...\n");
				  
				  // close the capture device and deallocate resources
				  pcap_close(handle);
				  n = 0;

				string arg_str(argv[numOfArgs+1]);
				files = files + arg_str + " ";
				numOfArgs++;
			}
			cout << files << endl;
			break;
		}
		numOfArgs--;
	}

	cout << "Hello world!" << endl ;
	return 0;
}