/***
  @file ip4_bit.c
  @author Jens Wehrenbrecht, feh
  @funcs ip4_bitstring, bitstring_ip4, ip4_cscan
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
  /fn ip4_bitstring
  /brief This function converts a IPv4 address into its binary representation with given prefix len
  /param out: ip4string    0-terminated destination address.
  /param in:  ip4address   The source address.
  /param in:  prefix       The net prefix bits (maximum 32 bits for IPv4).
  /return -1: lack of memory;  1: non valid IPv6 address; 0: successful converted.
*/

int ip4_bitstring(stralloc *ip4string, char *ip, unsigned int prefix)
{
  int i, j;
  char ip4[4];
  int count = 0;
  unsigned char number;
#ifdef BITSUBSTITUTION
  const char *letterarray = "abcdefghijklmnopqrstuvwxyz123456";
#endif

  if (ip4_cscan(ip,ip4) * 2.5 > prefix) return 1; /* a rough guess for the prefix length */
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
  /fn bitstring_ip4
  /brief This function takes an IPv4 bitstring and translates it to an IPv4 address + prefix
  /param in:  ip4string    The source address  (with '_' start token).
  /param out: ip4addr      0-terminated estination IPv4 address + net prefix (eg. 127.0.0.0/16).
  /return -1: lack of memory;  1: non valid IPv4 address; 0: successful converted.
*/

int bitstring_ip4(stralloc *ip4addr, stralloc *ip4string)
{
  int j;
  int num = 0;
  int value = 256;
  int prefix = ip4string->len - 1;
  
  if (prefix <= 1 || prefix > 32) return 1;

  for (j = 1; j <= prefix; j++) {
    if (ip4string->s[j] != '0')
      { num += (value/2); value /= 2; }
    else 
      { value /= 2; }
    if (j % 8 == 0 ) {
      if (!stralloc_catb(ip4addr,strnum,fmt_ulong(strnum,num))) return -1;
      if (j < 32) if (!stralloc_cats(ip4addr,".")) return -1;
      num = 0;
      value = 256;
    }
  }

  if (!stralloc_cats(ip4addr,"/")) return -1;
  if (!stralloc_catb(ip4addr,strnum,fmt_ulong(strnum,prefix))) return -1;
  if (!stralloc_0(ip4addr)) return -1;

  return 0;
}

/* ip4_cscan
   complementary to ip4_scan; but returns the number of decimals read 
*/

unsigned int ip4_cscan(const char *s,char ip[4])
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
  unsigned int n = 0;

  byte_zero(ip,4);
  len = 0;
  i = scan_ulong((char *)s,&u); if (!i) { return n; } ip[0] = u; s += i; len += i; n += i;
  if (*s != '.') { return n; } ++s; ++len;
  i = scan_ulong((char *)s,&u); if (!i) { return n; } ip[1] = u; s += i; len += i; n += i;
  if (*s != '.') { return n; } ++s; ++len;
  i = scan_ulong((char *)s,&u); if (!i) { return n; } ip[2] = u; s += i; len += i; n += i;
  if (*s != '.') { return n; } ++s; ++len;
  i = scan_ulong((char *)s,&u); if (!i) { return n; } ip[3] = u; s += i; len += i; n += i;
  return n;
}
