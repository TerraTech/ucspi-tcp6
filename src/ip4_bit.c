/***
  @file ip4_bit.c
  @author Jens Wehrenbrecht, feh
  @funcs getaddressasbit, getbitsasaddress
*/
#include "ip.h"
#include "byte.h"
#include "scan.h"
#include "str.h"
#include "fmt.h"
#include "ip_bit.h"

#define BITSUBSTITUTION

char strnum[FMT_ULONG];

/***
  /fn getaddressasbit
*/

int getaddressasbit(char *ip,int prefix,stralloc *ip4string)
{
  int i, j;
  char ip4[4];
  int count = 0;
  unsigned char number;
#ifdef BITSUBSTITUTION
  const char *letterarray = "abcdefghijklmnopqrstuvwxyz123456";
#endif
  
  if (!ip4_scan(ip,ip4)) return -1;
  if (!stralloc_copys(ip4string,"")) return -1;
  if (!stralloc_readyplus(ip4string,32)) return -1;

  for (i = 0; i < 4; i++) {
    number = (unsigned char) ip4[i];

    for (j = 7; j >= 0; j--) {
      if (number & (1<<j)) {
#ifdef BITSUBSTITUTION
        if (!stralloc_catb(ip4string,letterarray + count,1)) return -1;
#else
        if (!stralloc_cats(ip4string,"1")) return -1;
#endif
      } else {
        if (!stralloc_cats(ip4string,"0")) return -1;
      }
      count++;
      prefix--;
      if (prefix == 0) {
        if (!stralloc_0(ip4string)) return -1;
        return 0;
      }
    }
  }

  return 1;
}

/***
  /fn getbitsasaddress
*/

int getbitasaddress(stralloc *ip4string)
{
  stralloc ipaddr = {0};
  stralloc buffer = {0};
  int iplen;
  int num = 0;
  int value = 256;
  int prefix = ip4string->len - 1;
  
  if (!stralloc_copys(&buffer,"")) return -1;
  if (!stralloc_copys(&ipaddr,"")) return -1;
  
  for (iplen = 1; iplen <= prefix; iplen++) {
    if (!stralloc_copyb(&buffer,ip4string->s + iplen,1)) return -1;
    if (byte_diff(buffer.s,1,'0') != 0) 
      { num += (value/2); value /= 2; }
    else 
      { value /= 2; }
    if (iplen % 8 == 0 || iplen == prefix) {
      if (!stralloc_catb(&ipaddr,strnum,fmt_ulong(strnum,num))) return -1;
      if (iplen < 32) if (!stralloc_cats(&ipaddr,".")) return -1;
      num = 0;
      value = 256;
    }
  }
  
  if (!stralloc_copy(ip4string,&ipaddr)) return -1;
  if (!stralloc_cats(ip4string,"/")) return -1;
  if (!stralloc_catb(ip4string,strnum,fmt_ulong(strnum,prefix))) return -1;

  return 0;
}
