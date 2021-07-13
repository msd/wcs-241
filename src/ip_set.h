#ifndef IP_SET_H
#define IP_SET_H
#include <stdlib.h> /* exit */
#include <stdio.h> /* printf, fprintf, puts */
#include <stdint.h> /* uint32_t */
#include <inttypes.h> /* PRIu32 */

/** Set implementated using a sorted array. */
struct ip_set
{
	int
		size,		/* Number of elements currently stored */
		capacity,	/* Number of elements possible to be stored */
		unit_size;	/* Size (bytes) of each element */
	uint32_t *data; /* The data (elements) of the list */
};

/** 
 * Initialise set to allow for furture insertions of elements.
 * @arg ips
 *		The set to initialise
 */
void ip_set_init(struct ip_set* ips);

/**
 * Search for a specific element and remove it if found
 * @arg ips
 *		The set to act on
 * @arg a
 *		The element to search for and remove
 * @return
 *		0 given element not found
 *		1 given element was found and removed
 */
int ip_set_remove(struct ip_set* ips, uint32_t a);

/**
 * Check whether the set contains no elements
 * @arg ips
 *		The set to check for emptiness
 * @return
 *		0 the set is non-empty
 *		1 the set is empty
 */
int ip_set_is_empty(struct ip_set* ips);

/**
 * Empty the set.
 * @arg ips
 *		The set to be acted on
 */
void ip_set_clear(struct ip_set* ips);

/**
 * Get element in ASCENDING order of set.
 * @arg ips
 *		The set to get elerments from
 * @arg i
 *		Index of the element to be returned must be 0<=i<size
 * @return
 *		The i-th element in ASCENDING order of set.
 */
uint32_t ip_set_get(struct ip_set* ips, int a);

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
int ip_set_has(struct ip_set* ips, uint32_t ip);

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
int ip_set_add(struct ip_set* ips, uint32_t a);

/*
 * Output set in mathematical notation (elements in curly
 * brackets, separated by commas). No new line is printed.
 * @arg ips
 *		The set to output
 */
void ip_set_print(struct ip_set* ips);

/**
 * Free/deallocate resources of set
 * @arg ips
 *		The set to be acted on
 */
void ip_set_destroy(struct ip_set* ips);

#endif
