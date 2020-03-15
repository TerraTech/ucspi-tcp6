#include "byte.h"
#include "buffer.h"
#include "logmsg.h"
#include "env.h"
#include "rules.h"
#include "stralloc.h"
#include "ip.h"
#include "exit.h"
#include "open.h"
#include "ip_bit.h"

#define WHO "tcprulescheck"

void found(char *data,unsigned int datalen)
{
  unsigned int next0;
  stralloc ip6address = {0};
  
  buffer_puts(buffer_1,"rule ");

  if (byte_chr(rules_name.s,rules_name.len,'^') < rules_name.len) {		/* IPv6 CIDR */
    if (bitstringtoip6(&rules_name,&ip6address) == 1)
      stralloc_copys(&rules_name,ip6address.s);
    else
      logmsg(WHO,101,SYNTAX,"IPv6 address error!");
  }

  if (byte_chr(rules_name.s,rules_name.len,'_') < rules_name.len) {		/* IPv4 CIDR */
    if (getbitasaddress(&rules_name) == -1) 
      logmsg(WHO,101,SYNTAX,"IPv4 address error!");
  } 

  buffer_put(buffer_1,rules_name.s,rules_name.len);
  buffer_puts(buffer_1,":\n");
  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
        buffer_puts(buffer_1,"deny connection\n");
        buffer_flush(buffer_1);
        _exit(0);
      case '+':
        buffer_puts(buffer_1,"set environment variable ");
        buffer_puts(buffer_1,data + 1);
        buffer_puts(buffer_1,"\n");
        break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
  buffer_puts(buffer_1,"allow connection\n");
  buffer_flush(buffer_1);
  _exit(0);
}

int main(int argc,char **argv)
{
  char *fnrules;
  int fd;
  char *ip;
  char *info;
  char *host;

  fnrules = argv[1];
  if (!fnrules) {
    logmsg(WHO,100,USAGE,"rules.cdb");
  }

  ip = env_get("TCPREMOTEIP");
  if (!ip) ip = "::"; 
  info = env_get("TCPREMOTEINFO");
  host = env_get("TCPREMOTEHOST");

  fd = open_read(fnrules);
  if ((fd == -1) || (rules(found,fd,ip,host,info) == -1))
    logmsg(WHO,111,FATAL,B("unable to read: ",fnrules));

  buffer_putsflush(buffer_1,"default:\nallow connection\n");
  _exit(0);
}
