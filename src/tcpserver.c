#include <sys/types.h>
#include <unistd.h>
#include <sys/param.h>
#include <netdb.h>
#include "uint_t.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "logmsg.h"
#include "getoptb.h"
#include "pathexec.h"
#include "socket_if.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "dnsresolv.h"

#define WHO "tcpserver"

int verbosity = 1;
int flagkillopts = 1;
int flagdelay = 1;
char *banner = "";
int flagremoteinfo = 0;
int flagremotehost = 1;
int flagparanoid = 0;
unsigned long timeout = 26;
int ipv4socket = 0;
uint32 netif = 0;
int flagdualstack = 0;

static stralloc tcpremoteinfo;

uint16 localport;
char localportstr[FMT_ULONG];
char localip[16];
char localipstr[IP6_FMT];
static stralloc localhostsa;
char *localhost = 0;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[16];
char remoteipstr[IP6_FMT];
static stralloc remotehostsa;
char *remotehost = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;

char bspace[16];
buffer b;

/* ---------------------------- child */

int flagdeny = 0;
int flagallownorules = 0;
char *fnrules = 0;

void drop_nomem(void)
{
  logmsg(WHO,111,FATAL,"out of memory");
}
void cats(char *s)
{
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(char *ch)
{
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(char *s)
{
  char ch;
  int i;

  for (i = 0; i < 100; ++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t)
{
  if (!pathexec_env(s,t)) drop_nomem();
}
void drop_rules(void)
{
  logmsg(WHO,110,DROP,B("unable to read: ",fnrules));
}

void found(char *data,unsigned int datalen)
{
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
        flagdeny = 1;
        break;
      case '+':
        split = str_chr(data + 1,'=');
        if (data[1 + split] == '=') {
          data[1 + split] = 0;
          env(data + 1,data + 1 + split + 1);
        }
        break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit(int t)
{
  uint32 scope_id;
  int j;

  ipv4socket = ip6_isv4mapped(remoteip);

  if (socket_local(t,localip,&localport,&scope_id) == -1)
    logmsg(WHO,111,FATAL,"unable to get local address");
  if (flagkillopts) 
    socket_ipoptionskill(t);
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (ipv4socket) {
    remoteipstr[ip4_fmt(remoteipstr,remoteip + 12)] = 0;
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  } else {
    remoteipstr[ip6_fmt(remoteipstr,remoteip)] = 0;
    localipstr[ip6_fmt(localipstr,localip)] = 0;
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    log(WHO,B("pid ",strnum," from ",remoteipstr));
  }

  if (*banner) {
    buffer_init(&b,write,t,bspace,sizeof(bspace));
    if (buffer_putsflush(&b,banner) == -1)
      logmsg(WHO,111,FATAL,"unable to print banner");
  }

  if (!localhost)
    if (dns_name(&localhostsa,localip) == 0)
      if (localhostsa.len) {
        if (!stralloc_0(&localhostsa)) drop_nomem();
        localhost = localhostsa.s;
      }

  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (flagremotehost)
    if (dns_name(&remotehostsa,remoteip) == 0)
      if (remotehostsa.len) {
        if (flagparanoid) {
          if (dns_ip6(&tmp,&remotehostsa) == 0)
            for (j = 0; j + 16 <= tmp.len; j += 16)
              if (byte_equal(remoteip,16,tmp.s + j)) {
                flagparanoid = 0;
                break;
              }
            if (dns_ip4(&tmp,&remotehostsa) == 0)
              for (j = 0; j + 4 <= tmp.len; j += 4)
                if (byte_equal(remoteip,4,tmp.s + j)) {
                  flagparanoid = 0;
                  break;
                }
        }
        if (!flagparanoid) {
          if (!stralloc_0(&remotehostsa)) drop_nomem();
            remotehost = remotehostsa.s;
        }
      }

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout,netif) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }

  if (fnrules) {
    int fdrules;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != ENOENT) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,remoteipstr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1) drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,"tcpserver: ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) _exit(100);

  /* Set up environment late */

  env("PROTO",ip6_isv4mapped(remoteip)? "TCP":"TCP6");
  env("TCPLOCALIP",localipstr);
  env("TCPLOCALPORT",localportstr);
  env("TCPLOCALHOST",localhost);
  if (!ipv4socket) {
    env("TCP6LOCALIP",localipstr);
    env("TCP6LOCALHOST",localhost);
    env("TCP6LOCALPORT",localportstr);
    if (scope_id)
      env("TCP6INTERFACE",socket_getifname(scope_id));
  }
  env("TCPREMOTEIP",remoteipstr);
  env("TCPREMOTEPORT",remoteportstr);
  env("TCPREMOTEHOST",remotehost);
  if (!ipv4socket) {
    env("TCP6REMOTEIP",remoteipstr);
    env("TCP6REMOTEPORT",remoteportstr);
    env("TCP6REMOTEHOST",remotehost);
  }
  env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

}


/* ---------------------------- parent */

void usage(void)
{
  logmsg(WHO,100,USAGE,"tcpserver \
[ -46UxXpPhHrRoOdDqQv ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -I interface ] \
host port program");
}

unsigned long limit = 40;
unsigned long numchildren = 0;

int flag1 = 0;
unsigned long backlog = 20;
unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void)
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  log(WHO,B("status: ",strnum,"/",strnum2));
}

void sigterm(void)
{
  _exit(0);
}

void sigchld(void)
{
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      log(WHO,B("end ",strnum," status ",strnum2));
    }
    if (numchildren) --numchildren; printstatus();
  }
}

int main(int argc,char **argv)
{
  const char *hostname;
  int opt;
  struct servent *se;
  char *x;
  unsigned long u;
  int s;
  int t;

  while ((opt = getopt(argc,argv,"146dDvqQhHrRUXx:t:u:g:l:b:B:c:I:pPoO")) != opteof) {
    switch(opt) {
      case '1': flag1 = 1; break;
      case '4': ipv4socket = 1; break;
      case '6': ipv4socket = 0; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'h': flagremotehost = 1; break;
      case 'H': flagremotehost = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
                x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'x': fnrules = optarg; break;
      case 'X': flagallownorules = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case 'l': localhost = optarg; break;
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'B': banner = optarg; break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'I': netif = socket_getifidx(optarg); break;
      case 'p': flagparanoid = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'o': flagkillopts = 0; break;
      case 'O': flagkillopts = 1; break;
      default: usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  hostname = *argv++;
  if (!hostname) usage();
  if (str_equal(hostname,"") || str_equal(hostname,"0")) {
    if (ipv4socket) hostname = "0.0.0.0";
    else  hostname = "::";
  }
  if (str_equal(hostname,":0")) {
    flagdualstack = 1;
    hostname = "::";
  }

  x = *argv++;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"tcp");
    if (!se)
      logmsg(WHO,111,FATAL,B("unable to figure out port number for: ",x));
    uint16_unpack_big((char*)&se->s_port,&localport);
  }

  if (!*argv) usage();
 
  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);

  if (gid) if (prot_gid(gid) == -1)
    logmsg(WHO,111,FATAL,"unable to set gid");
  if (uid) if (prot_uid(uid) == -1)
    logmsg(WHO,111,FATAL,"unable to set uid");

  /* Name qualification */

  if (ip4_scan(hostname,localip)) {
    if (!stralloc_copys(&addresses,"")) drop_nomem();
    byte_copy(addresses.s,12,V4mappedprefix);
    byte_copy(addresses.s + 12,4,localip);
  } else if (ip6_scan(hostname,localip))
    if (!stralloc_copyb(&addresses,localip,16)) drop_nomem();

  if (!addresses.len) {
    if (!stralloc_copys(&tmp,hostname)) drop_nomem();
    if (dns_ip6_qualify(&addresses,&fqdn,&tmp) == -1)
      logmsg(WHO,111,FATAL,B("temporarily unable to figure out IP address for: ",hostname));
    if (addresses.len < 4)
      logmsg(WHO,111,FATAL,B("no IP address for: ",hostname));
  }
  byte_copy(localip,16,addresses.s);

  s = socket_tcp();
  if (s == -1)
    logmsg(WHO,111,FATAL,"unable to create socket");
  if (flagdualstack)
    socket_dualstack(s);
  if (socket_bind_reuse(s,localip,localport,netif) == -1)
    logmsg(WHO,111,FATAL,"unable to bind");
  if (socket_local(s,localip,&localport,&netif) == -1)
    logmsg(WHO,111,FATAL,"unable to get local address");
  if (socket_listen(s,backlog) == -1)
    logmsg(WHO,111,FATAL,"unable to listen");
  ndelay_off(s);

  if (ipv4socket)
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  else
    localipstr[ip6_fmt(localipstr,localip)] = 0;
  localportstr[fmt_ulong(localportstr,localport)] = 0;

  /* Initial setup */

  if (flag1) {
    buffer_init(&b,write,1,bspace,sizeof(bspace));
    buffer_puts(&b,localipstr);
    buffer_puts(&b," : ");
    buffer_puts(&b,localportstr);
    buffer_puts(&b,"\n");
    buffer_flush(&b);
  }

  close(0);
  close(1);
  printstatus();

  for (;;) {
    while (numchildren >= limit) sig_pause();

    sig_unblock(sig_child);
    if (flagdualstack)
      t = socket_accept6(s,remoteip,&remoteport,&netif);
    else
      t = socket_accept(s,remoteip,&remoteport,&netif);
    sig_block(sig_child);

    if (t == -1) continue;
    ++numchildren; printstatus();

    switch(fork()) {
      case 0:
        close(s);
        doit(t);
        if ((fd_move(0,t) == -1) || (fd_copy(1,0) == -1))
          logmsg(WHO,111,FATAL,"unable to set up descriptors");
        sig_uncatch(sig_child);
        sig_unblock(sig_child);
        sig_uncatch(sig_term);
        sig_uncatch(sig_pipe);
        pathexec(argv);
        logmsg(WHO,111,FATAL,B("unable to run: ",*argv));
      case -1:
        logmsg(WHO,111,FATAL,"unable to fork");

        --numchildren; printstatus();
    }
    close(t);
  }
}
