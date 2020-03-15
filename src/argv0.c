#include "pathexec.h"
#include "logmsg.h"

#define WHO "argv0"

int main(int argc,char **argv,char **envp)
{
  if (argc < 3) {
    logmsg(WHO,100,USAGE,"argv0 realname program [ arg ... ]");
  }	    
  pathexec_run(argv[1],argv + 2,envp);
  logmsg(WHO,111,FATAL,B("unable to run: ",argv[1]));
}
