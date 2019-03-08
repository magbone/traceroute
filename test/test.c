#include "traceroute.h"

int error_callback(char *msg)
{
      printf("%s\n", msg);
      return 1;
}

int success_callback(char *dest, long long *mss)
{
      printf("%s\t\t%lldms\t%lldms\t%lldms\n", dest, mss[0], mss[1], mss[2]);
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
      t->cmd.protocol = UDP;
      t->cmd.ttl = 45;
      t->cmd.addr = "43.254.218.121";
      traceroute_run_async(t, success_callback, error_callback);
      return 0;
}