#ifndef _CPKL_LIST_H_
#define _CPKL_LIST_H_

#ifndef CPKL_LEADER
#error Don't direct include this file, just include the "cpkl.h".
#endif

#include "cpkl_typedef.h"

typedef struct _cpkl_listhead {
	struct _cpkl_listhead	*prev;
	struct _cpkl_listhead	*next;
} cpkl_listhead_t;

#define get_container(p, type, field)					\
	(type *)(())

#endif
