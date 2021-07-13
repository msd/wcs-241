#include "ip_set.h"

/**
 * Check whether the set contains no elements
 * @arg ips
 *		The set to check for emptiness
 * @return
 *		0 the set is non-empty
 *		1 the set is empty
 */
int ip_set_is_empty(struct ip_set* ips)
{
	return ips->size == 0;
}

/**
 * Empty the set.
 * @arg ips
 *		The set to be acted on
 */
void ip_set_clear(struct ip_set* ips)
{
	ips->size = 0;
}

/**
 * The index k in the implementation array such that:
 * @return
 *		Index i, 0<=i<=size
 * 		Guarantees that 
 *		0 <= x < i		data[x] < a
 *
 *		x == i			data[x] == a, if a in set
 *						data[x] > a, if a not in set
 *
 *		i < x <= size	data[x] > a 
 */
static int ip_set_get_insert_pos(struct ip_set* ips, uint32_t a)
{
	if (ip_set_is_empty(ips))
	{
		/* empty set insert at start */
		return 0;
	}
	int
		beg = 0,
		end = ips->size - 1;
	/* for size 1 end = 0 hence end < beg */
	while (beg < end)
	{
		int mid = (beg + end) / 2;
		uint32_t m = ip_set_get(ips, mid);
		if (a == m)
		{
			beg = mid;
			end = mid;
		}
		else if (a > m)
		{
			beg = mid + 1;
		}
		else /* a < m */
		{
			end = mid - 1;
		}
	}
	/* By this point (beg == end) must be true */
	if (ip_set_get(ips, beg) >= a)
	{

		return beg;
	}
	else
	{
		return beg + 1;
	}
}

/**
 * Returns 1 when element was found and removed, otherwise 0.
 */
int ip_set_remove(struct ip_set* ips, uint32_t a)
{
	int index = ip_set_get_insert_pos(ips, a);
	if (index == ips->size || ip_set_get(ips, index) != a) /* not found */
	{
		return 0;
	}
	while (index < ips->size - 1)
	{
		ips->data[index] = ips->data[index + 1];
		index++;
	}
	ips->size--;
	return 1;
}

/**
 * Changes the allocated space of backing array by an integer
 * factor.
 * @arg ips
 *		The set to be acted on
 * @factor
 *		Factor by which the new capacity is calculated:
 *		New capacity = current capacity * factor
 * @return
 *		0 only when the realloc failed
 *		1 when successful realloc
 */
static int ip_set_realloc(struct ip_set* ips, int factor)
{
	ips->capacity *= factor;
	ips->data = realloc(ips->data, ips->capacity * ips->unit_size);
	if (!ips->data)
	{
		fprintf(stderr, "[ERROR] Failed to realloc set to capacity %d\n", ips->capacity);
		return 0;
	}
	return 1;
}

/**
 * Get element in ASCENDING order of set.
 * @arg ips
 *		The set to get elerments from
 * @arg i
 *		Index of the element to be returned must be 0<=i<size
 * @return
 *		The i-th element in ASCENDING order of set.
 */
uint32_t ip_set_get(struct ip_set* ips, int index)
{
	if (ip_set_is_empty(ips))
	{
		fprintf(stderr, "%s\n", "[ERROR] Attempted to get element from empty set");
		exit(2);
	}
	if (index < 0 || index >= ips->size)
	{
		fprintf(stderr, "[ERROR] Invalid index %d, size of set %d\n", index, ips->size);
		exit(3);
	}
	return ips->data[index];
}

/** 
 * Initialise set to allow for furture insertions of elements.
 * @arg ips
 *		The set to be initialised
 */
void ip_set_init(struct ip_set* ips)
{
	ips->size = 0;
	ips->capacity = 8; /* Initial capacity of IP set */
	ips->unit_size = sizeof(uint32_t); /* Size of uint32_t, 4 bytes per address */
	ips->data = malloc(ips->capacity * ips->unit_size);
	if (!ips->data)
	{
		fprintf(stderr, "%s\n", "[ERROR] Failed to initialise IP set (memory allocation error)");
		exit(5);
	}
}

/**
 * Search if an element is contained in the set
 * @arg ips
 *		The set to search in
 * @arg ip
 *		The eleement to search for
 * @return
 * 		1 if the set contains the element
 *		0 otherwise.
 */
int ip_set_has(struct ip_set* ips, uint32_t ip)
{
	if (ip_set_is_empty(ips))
	{
		return 0;
	}

	int i = ip_set_get_insert_pos(ips, ip);
	if (i == ips->size) /* End of array, definitel not it */
	{
		return 0;
	}
	else
	{
		return ip_set_get(ips, i) == ip;
	}
}

/**
 * Free/deallocate resources of set
 * @arg ips
 *		The set to be acted on
 */
void ip_set_destroy(struct ip_set* ips)
{
	free(ips->data);
}

/*
 * Returns 0 if failed to memory reallocation fault, 1 otherwise.
 */
static int ip_set_insert_at(struct ip_set* ips, int index, uint32_t a)
{
	if (ips->size == ips->capacity) /* Full capacity */
	{
		/* Make new room for more insertions */
		if (!ip_set_realloc(ips, 2))
		{
			return 0;
		}
	}

	if (index >= ips->size)
	{
		ips->data[ips->size++] = a;
		return 1;
	}
	else
	{
		int i = ips->size - 1;
		/* swap all elements starting from end until the desired
		 * index is reached (the index that needs to be emptied)
		 * to make room for the inserted element */
		if (index < 0)
		{
			fprintf(stderr, "[ERROR] Attempted to insert at index less than 0\n");
			exit(10);
		}
		while (i >= index)
		{
			/* move one position over */
			ips->data[i + 1] = ips->data[i];
			--i;
		}
		ips->data[index] = a;
		ips->size++;
		return 1;
	}
}

/**
 * Insert an element in the set.
 * @arg ips
 *		The set to be acted on
 * @arg a
 *		The element to be inserted
 * @return
 *		0 if the insertion was unsuccessful
 *		1 if the insertion successful
 */
int ip_set_add(struct ip_set* ips, uint32_t a)
{
	if (ip_set_is_empty(ips))
	{
		return ip_set_insert_at(ips, 0, a);
	}
	else
	{
		int i = ip_set_get_insert_pos(ips, a);
		if (i < ips->size && ip_set_get(ips, i) == a)
		{
			return 0;
		}
		return ip_set_insert_at(ips, i, a);
	}
}

/*
 * Output set in mathematical notation (elements in curly
 * brackets, separated by commas). No new line is printed.
 * @arg ips
 *		The set to output
 */
void ip_set_print(struct ip_set *ips)
{
	printf("%c", '{');
	if (!ip_set_is_empty(ips))
	{
		printf("%"PRIu32,ip_set_get(ips, 0));
		int i;
		for (i = 1; i < ips->size; ++i)
		{
			printf(", %"PRIu32, ip_set_get(ips, i));
		}
	}
	printf("%c", '}');
}