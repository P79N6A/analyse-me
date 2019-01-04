#ifndef _LIST_H_
#define _LIST_H_

#include <stddef.h>

#define LIST_POISON1  NULL
#define LIST_POISON2  NULL

typedef struct list_head
{
	struct list_head* next;
	struct list_head* prev;
} list_head_t;

static inline void init_list_head(struct list_head* list)
{
	list->next = list;
	list->prev = list;
}

/* 在链表头部插入节点 */

static inline void __list_add(struct list_head* node, struct list_head* prev, struct list_head* next)
{
	next->prev = node;
	node->next = next;
	node->prev = prev;
	prev->next = node;
}

static inline void list_add(struct list_head *node, struct list_head *head)
{
	__list_add(node, head, head->next);
}

static inline void list_insert_head( struct list_head* node, struct list_head* head)
{
	__list_add(node, head, head->next);
}

static inline void list_insert_tail(struct list_head *node, struct list_head *head)
{
	__list_add(node, head->prev, head);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void list_del(struct list_head *entry)
{
	struct list_head *eprev, *enext;
	eprev = entry->prev;
	enext = entry->next;
	enext->prev = eprev;
	eprev->next = enext;
	entry->next = NULL; 
	entry->prev = NULL;
}

#undef offset
#define offset(type, member)	\
	((size_t)&(((type*)0)->member))

#undef container_of
#define container_of(ptr, type, member)\
	({\
		const typeof(((type*)0)->member)*  __mptr = ptr;\
		(type*)((char*)__mptr - offset(type, member));\
	})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	 &pos->member != (head); 	\
	pos = list_entry(pos->member.next, typeof(*pos), member))

#define rlist_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	 &pos->member != (head); 	\
	pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
	n = list_entry(pos->member.next, typeof(*pos), member);	\
	&pos->member != (head); 					\
	pos = n, n = list_entry(n->member.next, typeof(*n), member))


struct hlist_head {
struct hlist_node *first;
};

struct hlist_node {
struct hlist_node *next, **pprev;
};

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define INIT_HLIST_NODE(ptr) ((ptr)->next = NULL, (ptr)->pprev = NULL)

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}


static inline void hlist_del_init(struct hlist_node *n)
{
	if (n->pprev)  {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
}
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}



/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
				struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_after(struct hlist_node *n,
				struct hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}



#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
for (pos = (head)->first; pos ; \
	 pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	 pos = n)

static inline struct hlist_node * hlist_search(struct hlist_head * hd, void * key,	int (*cmp)(struct hlist_node * in, void * key))
{
	struct hlist_node * pos;

	hlist_for_each(pos, hd)
	{
		if (cmp(pos, key))
		{
			return pos; 
		}
	}

	return NULL;
}

/**
* hlist_for_each_entry - iterate over list of given type
* @tpos:	the type * to use as a loop counter.
* @pos:	the &struct hlist_node to use as a loop counter.
* @head:	the head for your list.
* @member: the name of the hlist_node within the struct.
*/
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
		 pos && 		 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
		 pos = pos->next)

/**
* hlist_for_each_entry_continue - iterate over a hlist continuing after existing point
* @tpos:	the type * to use as a loop counter.
* @pos:	the &struct hlist_node to use as a loop counter.
* @member: the name of the hlist_node within the struct.
*/
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next; 					 \
		 pos && 		 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
		 pos = pos->next)

/**
* hlist_for_each_entry_from - iterate over a hlist continuing from existing point
* @tpos:	the type * to use as a loop counter.
* @pos:	the &struct hlist_node to use as a loop counter.
* @member: the name of the hlist_node within the struct.
*/
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
		 pos = pos->next)

/**
* hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
* @tpos:	the type * to use as a loop counter.
* @pos:	the &struct hlist_node to use as a loop counter.
* @n:		another &struct hlist_node to use as temporary storage
* @head:	the head for your list.
* @member: the name of the hlist_node within the struct.
*/
#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
		 pos && ({ n = pos->next; 1; }) &&				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
		 pos = n)


#endif

