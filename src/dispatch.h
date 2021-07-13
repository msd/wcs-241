#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pthread.h>
#include <pcap.h>
#include <assert.h>

#include "analysis.h"
#include "task_queue.h"

#define THREAD_COUNT 10

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);

/* Create all threads of thread pool */
void tpool_init(void);
#endif
