#include "traceroute.h"

int error_callback(char *msg)
{
      printf("%s\n", msg);
      return 1;
}

int success_callback(char *dest, long long *mss, INFO info)
{
      static int ccount = 1;
      if(info == (INFO)TIME_TO_EXCEEDED)
      printf("%d:\t%s\t\t%lldms\t%lldms\t%lldms\n", ccount++, dest, mss[0], mss[1], mss[2]);
      else if(info == TIME_OUT)
      printf("%d:\t*.*.*.*\t\t\t*\t*\t*\t\n", ccount++);
      else if(info == FINISHED)
      printf("finished\n");
      else if(info == DISTINATION_UNREACHABLE)
      printf("distination unreachable\n");
      return 1;
}

int main(int argc,char *argv[])
{

      traceroute *t;
      char *err_msg;
      if(traceroute_init(&t, &err_msg) == 0)
      {
            printf("%s\n", err_msg);
            return 1;
      }
      t->cmd.protocol = ICMP;
      t->cmd.ttl = 45;
      t->cmd.addr = "fbb.pw";
      traceroute_run_async(t, success_callback, error_callback);
      return 0;
}