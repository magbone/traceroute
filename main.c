#include "traceroute.h"

int main(int argc,char *argv[])
{
      
      #if defined(_PLATFORM_UNIX)
      traceroute_unix(argc,argv);
      #elif defined(_WIN32)
      traceroute_win(argc,argv);
      #endif 
      
      
      return 0;
}