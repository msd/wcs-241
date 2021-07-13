#include <getopt.h>
#include <signal.h> /* Signal handling */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h> /* timeval, gettimeofday */
#include <unistd.h> /* Signal handling */

#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"

/* Comment out to stop exiting when receiving Ctrl+C 
 * Warning: May have problems terminating the program!
 * Do so at your own risk. */
#define EXIT_ON_CTRLC

// Command line options
#define OPTSTRING "vi:"
static struct option long_opts[] = {
	{"interface", optional_argument, NULL, 'i'},
	{"verbose",   optional_argument, NULL, 'v'}
};

struct arguments {
	char *interface;
	int verbose;
};

/* GLOBAL VARS */

/* Keeps main sniff loop running when set to 0 */
char should_exit = 0;

/* Set for IP addresses, stored to detect SYN flooding attack */
struct ip_set unique_ips;

/* Count of TCP SYN packets received */
int total_syn_packets = 0;

/* Count of ARP packets received */
int total_arp_packets = 0;

/* Count of packets to blacklisted URLs */
int total_blacklist_viol = 0;

long long first_syn_time, last_syn_time;

/*pthread_mutex_t total_syn_packets_mutex;*/

/* END GLOBAL VARS */


void output_report(void)
{
	/* EXAMPLE OUTPUT
	 * Intrusion Detection Report:
	 * SYN flood attack possible
	 * 3204 SYN packets detected from 3204 IP addresses in 0.038504 seconds
	 * 4 ARP responses (cache poisoning)
	 * 5 URL Blacklist violations
	 */

	puts("Intrusion Detection Report:");
	
	/* SYN packet time in micro seconds */
	long long syn_time_us = last_syn_time - first_syn_time;
	/* and in seconds */
	double syn_time_s = ((double) syn_time_us) / ((double) 1000000);

	printf("SYN flood attack possible: ");

	if (total_syn_packets)
	{
		double syn_unique_ratio = ((double) (unique_ips.size)) / ((double) total_syn_packets);
		double syn_rate = ((double) total_syn_packets) / syn_time_s;
		int is_syn_flooding_possible = (syn_unique_ratio >= 0.9f) || (syn_rate > 100.0f);
		puts(is_syn_flooding_possible?"TRUE":"FALSE");
		printf("\t%d SYN packets detected from %d IP addresses in %6f seconds\n",
		    total_syn_packets, unique_ips.size, syn_time_s);
		printf("\tSYN unique ratio: %f\n", syn_unique_ratio);
		printf("\tSYN rate: %f SYN packets/sec\n", syn_rate);
	}
	else /* in case no SYN packets detected */
	{
		puts("FALSE\n\tNo SYN packets received");
	}

	printf("ARP cache poisoning possible: %s\n", total_arp_packets?"TRUE":"FALSE");
	printf("\t%d ARP packets received\n", total_arp_packets);

	printf("URL Blacklist violations: %d\n", total_blacklist_viol);
}

/**
 * Returns time since epoch in micro-seconds (millionths of 
 * a second) 
 * @return
 *		time in micro-seconds
 */
long long get_time(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return (t.tv_sec * 1000000LL) + t.tv_usec;
}

/**
 * Signal handling function for Ctrl+C (^C).
 */
void sig_handler(int signo)
{
	if (signo == SIGINT)
	{
		puts("\nReceived Ctrl+C\n");
		output_report();
#ifdef EXIT_ON_CTRLC
		/* Stop sniff loop, may have to wait for 1 more ETHERNET frame at pcap_next */
		should_exit = 1;
		puts("Program will exit after receiving another ETHERNET frame");
#endif
	}
}

void print_usage(char *progname)
{
	fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
	fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
	fprintf(stderr, "\t-i [interface]\tSpecify network interface to sniff\n");
	fprintf(stderr, "\t-v\t\tEnable verbose mode. Useful for Debugging\n");
}

int main(int argc, char *argv[])
{
	/* Register signal handler */
	if (signal(SIGINT, sig_handler) == SIG_ERR)
	{
		fprintf(stderr, "%s", "\n[WARNING] Cannot catch SIGINT (Failed to register signal handler)\n");
	}

	/* Initialise list for storing unique IPs so that they can be later used to detect SYN Flooding attack */
	ip_set_init(&unique_ips);
	tpool_init();

	// Parse command line arguments
	struct arguments args = {"eth0", 0}; // Default values
	int optc;
	while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF)
	{
		switch (optc)
		{
			case 'v':
				args.verbose = 1;
				break;
			case 'i':
				args.interface = strdup(optarg);
				break;
			default:
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	// Print out settings
	printf("%s invoked. Settings:\n", argv[0]);
	printf("\tInterface: %s\n\tVerbose: %d\n", args.interface, args.verbose);
	// Invoke Intrusion Detection System
	sniff(args.interface, args.verbose);

	/*pthread_mutex_destroy(&total_syn_packets_mutex);*/
	ip_set_destroy(&unique_ips);
	return 0;
}
