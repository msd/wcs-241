#include "task_queue.h"

void enqueue(struct queue* q, const unsigned char* data, size_t n, int verbose)
{
	struct queueitem* newitem = malloc(sizeof(struct queueitem));
	newitem->data = malloc(n);
	if (!newitem || !newitem->data)
	{
		fprintf(stderr, "%s\n", "FAILED TO ALLOCATE NEW TASK QUEUE ITEM");
		exit(1);
	}
	newitem->verbose = verbose;
	newitem->next = NULL;
	memcpy(newitem->data, data, n);

	if (q->head) /* Not empty */
	{
		struct queueitem* current = q->head;
		while (current->next)
		{
			current = current->next;
		}
		current->next = newitem;
	}
	else /* was empty */
	{
		q->head = newitem;
	}
}

struct queueitem* dequeue(struct queue* q)
{
	if (!q->head)
	{
		return NULL;
	}
	struct queueitem* t = q->head;
	q->head = q->head->next;
	return t;
}