#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <stdlib.h>
#include <netinet/if_ether.h>	/* ether_header */
#include <netinet/ip.h>			/* iphdr */
#include <netinet/tcp.h>		/* tcphdr */
#include <netinet/udp.h>		/* udphdr */
#include <netinet/in.h>			/* net to host byte order (ntohs and friends) */
#include <pcap.h>
#include <string.h>				/* strcasestr, memcpy */
#include <ctype.h> /* tolower */
#include <pthread.h>			/* pthread_mutex_t */

#include "ip_set.h"				/* struct ip_set */

/** 
 * In: 32 bit (uint32_t) int (host byte ordering)
 * Out: Print address with dot separators
 */
void print_inet_addr(uint32_t);

/**
 *	In: Takes an array of 6 bytes (unsigned char)
 *	Out: Prints MAC address in hexadecimal, no new line, colon (:) as byte separator.
 *	     Pads out bytes < than 2 hex digits (decimal 0-15)
 */ 
void print_mac(const unsigned char*);

/* Returns 0 if any of the following conditions are satisfied
 * the SYN flag is zero
 * any other flag (ACK, RST, etc) are non-zero
 */
int is_syn_packet(struct tcphdr* tcp_h);

void analyse(const unsigned char*, int);

#endif
