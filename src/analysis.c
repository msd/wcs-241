#include "analysis.h"
/* Includes are in header file */

/* Check if character is in the ASCII printable range. */
#define IS_PRINTABLE(c) (((unsigned char)(c)) >= 0x20 && ((unsigned char)(c)) <= 0x7e)

extern struct ip_set unique_ips;
extern int total_syn_packets;
extern int total_arp_packets;
extern int total_blacklist_viol;
extern long long first_syn_time, last_syn_time;
extern long long get_time(void);

pthread_mutex_t
	/* Resources mutexed
	 * unique_ips, total_syn_packets,
	 * last_syn_time, first_syn_time */
	syn_mutex = PTHREAD_MUTEX_INITIALIZER,
	/* Resources mutexed: total_arp_packets */
	arp_mutex = PTHREAD_MUTEX_INITIALIZER,
	/* Resources mutexed: total_blacklist_viol */
	blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Control during compilation of messages 
 * verbose command line argument overrides all to 1 */
static const int
	showether = 0,
	showarp   = 0,
	showipv4  = 0,
	showtcp   = 0,
	show_detections = 1;

/** 
 * In: 32 bit (uint32_t) int (host byte ordering)
 * Out: Print address with dot separators
 */
void print_inet_addr(uint32_t a)
{
	// (void *data)
	// unsigned long a = (unsigned long) ntohl(*((long*) data));
	long i;
	for (i = 3; i >= 0; --i)
	{
		printf("%lu", (a >> (i * 8L)) % 256L);
		if (i > 0)
		{
			printf("%s", ".");
		}
	}
	// printf("%lu.%lu.%lu.%lu", a >> 24, (a >> 16) % 256, (a >> 8) % 256, a % 256);
}

/**
 *	In: Takes an array of 6 bytes (unsigned char)
 *	Out: Prints MAC address in hexadecimal, colon (:) as
 *       byte separator. Pads out bytes < than 2 hex digits (decimal 0-15)
 *      
 */
void print_mac(const unsigned char* data)
{
	printf("%02hhx", data[0]);
	int i;
	for (i = 1; i < 6; ++i)
	{
		printf(":");
		printf("%02hhx", data[i]);
	}
}

/**
 * Compares the two strings if the beginning of the first
 * argument is exactly the second argument for the first n
 * bytes. Neither are null terminated hence caller must
 * determine how many bytes need to be checked. Comparison
 * ignores case (standard tolower function is used).
 * @arg s1
 *		The first string to be compared
 * @arg s2
 *		The second string to be compared
 * @return 
 *		<0 
 *		0   two strings are the same
 *		>0  first different character in str
 */
int memcmp_nocase(const char *s1, const char *s2, size_t n)
{
	int i;
	for (i = 0; i < n; ++i)
	{
		int d = tolower(s2[i]) - tolower(s1[i]);
		if (d != 0)
		{
			return d;
		}
	}
	return 0;
}

/**
 * Examines a TCP packet's flags and returns whether ONLY
 * its SYN flag is enabled.
 * @arg tcp_h
 *		The packet to be examined
 * @return
 *		1 iff of all flags only the SYN flag is enabled
 *		0 otherwise.
 */
int is_syn_packet(struct tcphdr* tcp_h)
{
	return !(tcp_h->th_flags ^ TH_SYN);
	/* just the syn flag must be true, equivalent below */
	/*return tcp_h->syn
	    && (!tcp_h->fin)
	    && (!tcp_h->rst)
	    && (!tcp_h->psh)
	    && (!tcp_h->ack)
	    && (!tcp_h->urg);*/
}

/**
 * Just like strstr but with raw bytes rather than null
 * terminated strings. The objective is to find the needle
 * in the haystack (names from linux man pages). If it is
 * found a pointer to its first occurence is returned
 * otherwise a NULL pointer is returned instead.
 * @arg haystack
 *		The memory to be scanned
 * @arg haystacklen
 *		Length of memory to be scanned
 * @arg needle
 *		The item that will be searched for
 * @arg needle
 *		Length of item that will be searched for
 * @return
 *		Pointer to first occurence of item in main memory,
 *		or NULL if not found.
 */
const char *memmem(const char *haystack, size_t haystacklen, const char *needle, size_t needlelen)
{
	int i = 0;
	while (i <= haystacklen - needlelen)
	{
		if (memcmp(haystack + i, needle, needlelen) == 0)
		{
			return haystack + i;
		}
		++i;
	}
	return NULL;
}

/**
 * Just like memmem but ignores case.
 * @arg haystack
 *		The memory to be scanned
 * @arg haystacklen
 *		Length of memory to be scanned
 * @arg needle
 *		Item that will be searched for
 * @arg needle
 *		Length of item that will be searched for
 * @return
 *		Pointer to first occurence of item in main memory,
 *		or NULL if not found.
 */
const char *memmem_nocase(const char *haystack, size_t haystacklen, const char *needle, size_t needlelen)
{
	int i = 0;
	while (i <= haystacklen - needlelen)
	{
		if (memcmp_nocase(haystack + i, needle, needlelen) == 0)
		{
			return haystack + i;
		}
		++i;
	}
	return NULL;
}

/**
 * Given a string checks if it is an HTTP request and if so if it is to one
 * (and only) blacklisted urls.
 * @arg s
 *		Given string to check, not null terminated.
 * @arg
 * 		n Length of string 
 * @return
 *		1 iff the given string is both an HTTP request and it violates
 *		the pre-determined blacklist, otherwise a 0 is returned. (www.telegraph.co.uk)
 */
int is_blacklist_req(const char* s, int n)
{
	static const char* blacklist_domain = "www.telegraph.co.uk";

	/* first newline */
	const char* nl = memchr(s, '\n', n); /* Possibly returns NULL if no \n */
	if (!nl)
	{
		/* Found no new lines hence not possible to be HTTP request */
		return 0;
	}
	/* Ignore possible Carriage Return */
	int firstlinelen = nl - s - (*(nl - 1)=='\r'?1:0);

	/* HTTP REQUEST CHECK
	 * Case insensitive test of first line of given string
	 * contains substring "HTTP" (case sensitive as per RFC 2626)
	 */
	if (!memmem(s, firstlinelen, "HTTP", 4)) /* Is NOT HTTP reqeust */
	{
		return 0;
	}

	/* BLACKLIST CHECK
	 * Parsing headers, line by line to check for Host header
	 */
	int linestart = (nl-s) + 1;
	while (linestart < n)
	{
		int next_nl = linestart + 1;
		while (next_nl < n && s[next_nl] != '\n') ++next_nl;
		/* length of line accounting for possible Carriage Return */
		int len = next_nl - linestart - (s[next_nl - 1] == '\r'?1:0);
		if (len == 0) /* An empty line signifies end of headers */
		{
			/* Host header not found */ 
			break;
		}
		printf("%.*s\n", len, s + linestart);
		/* HTTP headers are case insensitive, as is the domain name (unlike complete URL) */
		if (memcmp_nocase(s + linestart,"Host",4) == 0) /* Found HOSTS header */
		{
			if (memmem_nocase(s + linestart, n - len, blacklist_domain, strlen(blacklist_domain)))
			{
				/* Domain is blacklisted */
				return 1;
			}
			/* Return since domain is not blacklisted */
			break;
		}
		linestart = next_nl + 1;
	}
	return 0;
}

void analyse(const unsigned char *packet, int verbose)
{
	/* BEGIN ETHERNET DATA */
	struct ether_header *edata = (struct ether_header*) packet;
	if (showether)
	{
		printf("Ether Src MAC: "); print_mac(edata->ether_shost); printf("\n");
		printf("Ether Dest MAC: ");	print_mac(edata->ether_dhost); printf("\n");
		printf("Ether Type: 0x%hx\n", ntohs(edata->ether_type));
	}
	unsigned short ethertype = ntohs(edata->ether_type);
	const unsigned char* eth_payload = packet + ETH_HLEN;
	/* END ETHERNET DATA */

	if (ethertype < 1536)
	{
		/* Only EtherType >= 1536 is Ethernet II */
		fprintf(stderr, "%s\n", "[ERROR] Received frame with unsupported Ethernet protocol (Ethernet II suppored only)\n");
		exit(1);
	}
	
	/* EtherTypes
	 * 0x0800 IPv4
	 * 0x0806 ARP
	 * 0x86DD IPv6
	 */
	if (ethertype == 0x0800) /* IPv4 */
	{
		/* BEGIN IP DATA */
		struct ip *ipv4_header = (struct ip*) eth_payload;
		uint32_t src_ipa = ntohl(ipv4_header->ip_src.s_addr);
		if (showipv4 || verbose)
		{
			printf("IP Ver: %hhu\n", ipv4_header->ip_v);
			printf("IP Header Len: %hhu (32 bit words)\n", ipv4_header->ip_hl);
			printf("IP Type of Service: %hhu\n", ipv4_header->ip_tos);
			printf("IP Len: %hu\n", ntohs(ipv4_header->ip_len));
			printf("IP Protocol: %hu\n", ntohs(ipv4_header->ip_p));
			printf("IP Src Addr: "); print_inet_addr(src_ipa); puts("");
			printf("IP Dst Addr: "); print_inet_addr(ntohl(ipv4_header->ip_dst.s_addr)); puts("");
		}
		const unsigned char *ip_payload = eth_payload + (ipv4_header->ip_hl * 4);
		/* END IP DATA */

		/* IP protool legend
		 * 0x01 ICMP
		 * 0x06 TCP
		 * 0x11 UDP
		 */
		if (ipv4_header->ip_p == 0x06) /* TCP */
		{
			/* BEGIN TCP DATA */
			struct tcphdr* tcp_header = (struct tcphdr*) ip_payload;
			const int
				tcp_src = ntohs(tcp_header->source),
				tcp_dest = ntohs(tcp_header->dest);
			if (showtcp || verbose)
			{
				printf("TCP Src Port: %hu\n", tcp_src);
				printf("TCP Dest Port: %hu\n", tcp_dest);
				printf("TCP Flags: ");
				if (tcp_header->syn)
				{
					printf("SYN ");
				}
				if (tcp_header->fin)
				{
					printf("FIN ");
				}
				if (tcp_header->rst)
				{
					printf("RST ");
				}
				if (tcp_header->psh)
				{
					printf("PSH ");
				}
				if (tcp_header->ack)
				{
					printf("ACK ");
				}
				if (tcp_header->urg)
				{
					printf("URG");
				}
				puts("");
			}
			const int
				tcp_hdr_len = tcp_header->doff * 4,
				tcp_payload_len = ntohs(ipv4_header->ip_len) - (ipv4_header->ip_hl * 4) - tcp_hdr_len;
			const unsigned char *tcp_payload = ip_payload + tcp_hdr_len;
			/* END TCP DATA */

			/* SYN FLOODING DETECT */
			if (is_syn_packet(tcp_header))
			{
				if (show_detections || verbose)
				{
					puts("SYN PACKET RECEIVED");
				}
				pthread_mutex_lock(&syn_mutex);
				last_syn_time = get_time();
				if (!total_syn_packets)
				{
					first_syn_time = last_syn_time;
				}
				++total_syn_packets;
				if (ip_set_add(&unique_ips, src_ipa) && (show_detections || verbose))
				{
					printf("/!\\ New SYN Src IP: "); print_inet_addr(src_ipa); puts("");
				}
				pthread_mutex_unlock(&syn_mutex);
			}

			/* BLACKLISTED URL DETECTION */
			if (tcp_dest == 80 && is_blacklist_req((char*) tcp_payload, tcp_payload_len))
			{
				if (show_detections || verbose)
				{
					puts("BLACKLISTED DOMAIN DETECTED");
				}
				pthread_mutex_lock(&blacklist_mutex);
				++total_blacklist_viol;
				pthread_mutex_unlock(&blacklist_mutex);
			}
		}
		else if (verbose)
		{
			fprintf(stderr, "=== UNKNOWN/UNIMPLEMENTED IP Protocol 0x%hhx ===\n", ipv4_header->ip_p);
		}
	}
	else if (ethertype == 0x0806) /* ARP */
	{
		/* BEGIN ARP DATA */
		struct ether_arp *arp_data = (struct ether_arp*) eth_payload;
		if (showarp || verbose)
		{
			printf("ARP HTYPE: 0x%hx\n", ntohs(arp_data->ea_hdr.ar_hrd));
			printf("ARP PTYPE: 0x%hx\n", ntohs(arp_data->ea_hdr.ar_pro));
			printf("ARP HLEN: %hhu\n", arp_data->ea_hdr.ar_hln);
			printf("ARP PLEN: %hhu\n", arp_data->ea_hdr.ar_pln);
			printf("ARP OPER: %hx\n", ntohs(arp_data->ea_hdr.ar_op));
		}
		/* END ARP DATA */

		if (show_detections || verbose)
		{
			puts("ARP packet detected");
		}
		pthread_mutex_lock(&arp_mutex);
		++total_arp_packets;
		pthread_mutex_unlock(&arp_mutex);
	}
	else if (verbose)
	{
		fprintf(stderr, "[WARNING] Packet received with unknown EtherType: 0x%hx", ethertype);
	}

/*
	puts("\nDUMP FOLLOWS\n----------------------");
	dump(packet, header->caplen);
	puts("DUMP END\n");
*/
	/*puts("\n");*/
}
