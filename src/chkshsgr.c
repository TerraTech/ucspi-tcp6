#include "exit.h"

extern int getgroups(int, short[4]);
extern int setgroups(int, short[4]);

int main()
{
  short x[4];

  x[0] = x[1] = 0;
  if (getgroups(1,x) == 0) if (setgroups(1,x) == -1) _exit(1);
  _exit(0);
}
