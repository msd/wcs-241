#include "dispatch.h"
/* Includes are in header file */

extern int should_exit;

pthread_t tpool[THREAD_COUNT];
struct queue task_q;
pthread_mutex_t q_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_cond = PTHREAD_COND_INITIALIZER;

/* Loop to be executed by worker threads */
void* thread_loop(void *arg)
{
	while (!should_exit)
	{
		struct queueitem* item;
		pthread_mutex_lock(&q_mutex);
		while (!(item = dequeue(&task_q)) && !should_exit)
		{
			pthread_cond_wait(&task_cond, &q_mutex);
		}
		pthread_mutex_unlock(&q_mutex);

		if (item)
		{
			if (!should_exit)
			{
				analyse(item->data, item->verbose);
			}
			free(item->data);
			free(item);
		}
	}
	return NULL;
}

/* Called to create all threads */
void tpool_init(void)
{
	int i;
	for (i = 0; i < THREAD_COUNT; ++i)
	{
		pthread_create(tpool + i, NULL, &thread_loop, NULL);
	}
}

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose)
{
	pthread_mutex_lock(&q_mutex);
	enqueue(&task_q, packet, header->caplen, verbose);
	pthread_cond_signal(&task_cond);
	pthread_mutex_unlock(&q_mutex);
}
