#include "sig.h"
#include "wait.h"
#include "fork.h"
#include "buffer.h"
#include "logmsg.h"
#include "exit.h"

#define WHO "mconnect-io"

extern int kill(int,int);

char outbuf[512];
buffer bo;

char inbuf[512];
buffer bi;

ssize_t myread(int fd,char *buf,int len)
{
  buffer_flush(&bo);
  return read(fd,buf,len);
}

int main()
{
  int pid;
  int wstat;
  char ch;

  sig_ignore(sig_pipe);

  pid = fork();
  if (pid == -1) logmsg(WHO,111,FATAL,"unable to fork");

  if (!pid) {
    buffer_init(&bi,myread,0,inbuf,sizeof(inbuf));
    buffer_init(&bo,write,7,outbuf,sizeof(outbuf));

    while (buffer_get(&bi,&ch,1) == 1) {
      if (ch == '\n') buffer_put(&bo,"\r",1);
      buffer_put(&bo,&ch,1);
    }
    _exit(0);
  }

  buffer_init(&bi,myread,6,inbuf,sizeof(inbuf));
  buffer_init(&bo,write,1,outbuf,sizeof(outbuf));

  while (buffer_get(&bi,&ch,1) == 1)
    buffer_put(&bo,&ch,1);

  kill(pid,sig_term);
  wait_pid(&wstat,pid);

  _exit(0);
}
