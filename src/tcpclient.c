#include <unistd.h>
#include <sys/param.h>
#include <netdb.h>
#include <netinet/in.h>
#include "sig.h"
#include "exit.h"
#include "getoptb.h"
#include "uint_t.h"
#include "fmt.h"
#include "scan.h"
#include "str.h"
#include "ip.h"
#include "socket_if.h"
#include "fd.h"
#include "stralloc.h"
#include "buffer.h"
#include "error.h"
#include "logmsg.h"
#include "pathexec.h"
#include "timeout.h"
#include "timeoutconn.h"
#include "dnsresolv.h"
#include "byte.h"
#include "remoteinfo.h"

#define WHO "tcpclient"

void nomem(void)
{
  logmsg(WHO,111,FATAL,"out of memory");
}
void usage(void)
{
  logmsg(WHO,100,USAGE,"tcpclient \
[ -46hHrRdDqQv ] \
[ -i iplocal ] \
[ -p portlocal ] \
[ -T timeoutconn ] \
[ -l localname ] \
[ -t timeoutinfo ] \
[ -I interface ] \
host port program");
}

int verbosity = 1;
int flagdelay = 1;
int flagremoteinfo = 1;
int flagremotehost = 1;
unsigned long itimeout = 26;
unsigned long ctimeout[2] = { 2, 58 };
uint32 netif = 0;
int ipv4socket = 0;

char iplocal[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
uint16 portlocal = 0;
char *forcelocal = 0;

char ipremote[16];
uint16 portremote;

const char *hostname;
const char *loopback = "127.0.0.1";
static stralloc addresses;
static stralloc moreaddresses;

static stralloc tmp;
static stralloc fqdn;
char strnum[FMT_ULONG];
char ipstr[IP6_FMT];

char seed[128];

int main(int argc,char **argv)
{
  unsigned long u;
  int opt;
  char *x;
  int j;
  int s;
  int cloop;

  dns_random_init(seed);

  close(6);
  close(7);
  sig_ignore(sig_pipe);

  while ((opt = getopt(argc,argv,"46dDvqQhHrRi:p:t:T:l:I:")) != opteof)
    switch(opt) {
      case '4': ipv4socket = 1; break;
      case '6': ipv4socket = 0; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'l': forcelocal = optarg; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&itimeout); break;
      case 'T': j = scan_ulong(optarg,&ctimeout[0]);
                if (optarg[j] == '+') ++j;
                scan_ulong(optarg + j,&ctimeout[1]);
                break;
      case 'i': if (!ip6_scan(optarg,iplocal)) usage(); break;
      case 'I': netif = socket_getifidx(optarg); break;
      case 'p': scan_ulong(optarg,&u); portlocal = u; break;
      default: usage();
    }
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;

  hostname = *argv;
  if (!hostname || str_equal((char *)hostname,"")) usage();
  if (str_equal((char *)hostname,"0")) hostname = loopback;

  x = *++argv;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    portremote = u;
  else {
    struct servent *se;
    se = getservbyname(x,"tcp");
    if (!se)
      logmsg(WHO,111,FATAL,B("unable to figure out port number for: ",x));
    uint16_unpack_big((char *)&se->s_port,&portremote);
    /* i continue to be amazed at the stupidity of the s_port interface */
  }

  if (!*++argv) usage();


  if (ipv4socket) {
     if (ip4_scan(hostname,ipremote)) {
       if (!stralloc_copyb(&addresses,(char *)V4mappedprefix,12)) nomem();
       byte_copy(addresses.s + 12,4,ipremote);
     }
  } else if (ip6_scan(hostname,ipremote))
     if (!stralloc_copyb(&addresses,ipremote,16)) nomem();

  if (!addresses.len) {
    if (!stralloc_copys(&tmp,hostname)) nomem();
     if (dns_ip6_qualify(&addresses,&fqdn,&tmp) == -1)
       logmsg(WHO,111,FATAL,B("unable to figure out IP address for: ",(char *)hostname));
  }
  if (addresses.len < 16) 
       logmsg(WHO,111,FATAL,B("no IP address for: ",(char *)hostname));

  if (addresses.len == 16) {
     ctimeout[0] += ctimeout[1];
     ctimeout[1] = 0;
  }

  for (cloop = 0; cloop < 2; ++cloop) {
    if (!stralloc_copys(&moreaddresses,"")) nomem();
    for (j = 0; j + 16 <= addresses.len; j += 16) {
      ipv4socket =  ip6_isv4mapped(addresses.s + j);
      s = socket_tcp();
      if (s == -1)
        logmsg(WHO,111,FATAL,"unable to create socket");
      if (socket_bind(s,iplocal,portlocal,netif) == -1)
        logmsg(WHO,111,FATAL,"unable to bind socket");
      if (timeoutconn(s,addresses.s + j,portremote,ctimeout[cloop],netif) == 0)
        goto CONNECTED;
      close(s);
      if (!cloop && ctimeout[1] && (errno == ETIMEDOUT)) {
        if (!stralloc_catb(&moreaddresses,addresses.s + j,16)) nomem();
      }
      else {
        strnum[fmt_ulong(strnum,portremote)] = 0;
        if (ip6_isv4mapped(addresses.s + j))
          ipstr[ip4_fmt(ipstr,addresses.s + j + 12)] = 0;
        else
          ipstr[ip6_fmt(ipstr,addresses.s + j)] = 0;
      }
    }
    if (!stralloc_copy(&addresses,&moreaddresses)) nomem();
  }
  logmsg(WHO,-99,DROP,B("unable to connected to: ",ipstr," port: ",strnum));

  _exit(111);


  CONNECTED:

  if (!flagdelay)
    socket_tcpnodelay(s); /* if it fails, bummer */

  if (socket_local(s,iplocal,&portlocal,&netif) == -1)
    logmsg(WHO,111,FATAL,"unable to get local address");

  if (ip6_isv4mapped(iplocal) || byte_equal(iplocal,16,V6any))
    ipv4socket = 2;

  if (!pathexec_env("PROTO",ipv4socket?"TCP":"TCP6")) nomem();

  strnum[fmt_ulong(strnum,portlocal)] = 0;
  if (!pathexec_env("TCPLOCALPORT",strnum)) nomem();

  if (!ipv4socket) {
    ipstr[ip6_fmt(ipstr,iplocal)] = 0;
    if (!pathexec_env("TCP6LOCALIP",ipstr)) nomem();
    if (!pathexec_env("TCP6LOCALPORT",strnum)) nomem();
  } else
    ipstr[ip4_fmt(ipstr,iplocal + 12)] = 0;
  if (!pathexec_env("TCPLOCALIP",ipstr)) nomem();

  x = forcelocal;
  if (!x)
    if (dns_name6(&tmp,iplocal) != -1) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPLOCALHOST",x)) nomem();

  if (socket_remote(s,ipremote,&portremote,&netif) == -1)
    logmsg(WHO,111,FATAL,"unable to get remote address");

  strnum[fmt_ulong(strnum,portremote)] = 0;
  if (!pathexec_env("TCPREMOTEPORT",strnum)) nomem();

  if (!ipv4socket) {
    ipstr[ip6_fmt(ipstr,ipremote)] = 0;
    if (!pathexec_env("TCP6REMOTEIP",ipstr)) nomem();
    if (!pathexec_env("TCP6REMOTEPORT",strnum)) nomem();
  } else
    ipstr[ip4_fmt(ipstr,ipremote + 12)] = 0;
  if (!pathexec_env("TCPREMOTEIP",ipstr)) nomem();

  if (verbosity >= 2)
    log(WHO,B("connected to ",ipstr," port ",strnum));

  x = 0;
  if (flagremotehost)
    if (dns_name6(&tmp,ipremote) != -1) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPREMOTEHOST",x)) nomem();

  x = 0;
  if (flagremoteinfo)
    if (remoteinfo(&tmp,ipremote,portremote,iplocal,portlocal,itimeout,netif) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPREMOTEINFO",x)) nomem();

  if (fd_move(6,s) == -1)
    logmsg(WHO,111,FATAL,"unable to set up descriptor 6");
  if (fd_copy(7,6) == -1)
    logmsg(WHO,111,FATAL,"unable to set up descriptor 7");
  sig_uncatch(sig_pipe);

  pathexec(argv);
  logmsg(WHO,111,FATAL,B("unable to run: ",*argv));
}
