
# Packet Analyser - Terminal utility for offline packet analysis

## Usage:

	./isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...
	[-h]: prints help on the command line, which contains usage of the application
	[-a aggr-key]: aggr-key = { srcip, dstip, srcmac, dstmac, srcport, dstport }
	[-s sort-key]: sort-key = { packets, bytes }
	[-l limit]: limit = { 0, 1, 2, ..., n }
	[-f filter-expression]: filter-expression example: "src host 2001:db8::1"
	file ... - unlimited count of input files

## Description:

	Application provides simple network flow analysis on 
	layer of network interface, network layer and transport layer and 
	supports protocols such as Ethernet, IEEE 802.1Q, 802.1ad, IPv4, IPv6,
	ICMPv4, ICMPv6, TCP, UDP. Application also consider IP packet fragmentation,
	IPv6 extended headers encapsulation and ICMP error messages.