#ifndef CS241_TASK_QUEUE_H
#define CS241_TASK_QUEUE_H

#include <stdio.h> /* fprintf */
#include <stdlib.h> /* malloc */
#include <string.h> /* memcpy */

/* Linked list implementation of queue */
struct queueitem
{
	unsigned char* data;
	int verbose;
	struct queueitem *next;
};
/* Only need to store pointer to head of linked list. */
struct queue
{
	struct queueitem* head;
};

/* Makes of copy of given data of size n and stores it in a queue item.
 * Do not forget to free pointer after using. */
void enqueue(struct queue* q, const unsigned char* data, size_t n, int verbose);
/* Pop the oldest item that is in the queue (FIFO) 
 * Do not forget to free data pointer after done */
struct queueitem* dequeue(struct queue* q);

#endif