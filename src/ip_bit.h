#ifndef IP_BIT_H
#define IP_BIT_H

#include "stralloc.h"

extern int getaddressasbit(char *, int, stralloc *);
extern int getbitasaddress(stralloc *);
extern void getnum(char *,int,unsigned long *);

extern int ip6tobitstring(char *, stralloc *, unsigned int);
extern int bitstringtoip6(stralloc *, stralloc *);
extern unsigned int ip6_expandaddr(char *, stralloc *);

#endif
