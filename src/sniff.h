#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "dispatch.h"

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

#endif
