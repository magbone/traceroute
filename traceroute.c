#include "traceroute.h"


void IP_packet_create(IP_packet_t **t,  u_int8_t ttl)
{
      *t = (IP_packet_t *)malloc(sizeof(IP_packet_t));
      if(t == NULL)
      {
            printf("Error: Init failed.\n");
            exit(0);
      }
      (*t)->protocol = 0x45;
      (*t)->type_of_service = 0;
      (*t)->length = sizeof(IP_packet_t);
      (*t)->indentification = 0;
      (*t)->flags_fragmentOffset = 0;
      (*t)->ttl = ttl;
      (*t)->protocol = 1;
      (*t)->header_checksum = 0;
      //(*t)->source_addr = 0;
      //(*t)->remote_addr = 0;
}

void IPCMP_packet_clip(char *buffer,size_t buffer_size)
{

}

void traceroute(int argc,char *argv[])
{
      //command

      int sockfd;
      struct sockaddr_in remote_addr;

      int ttl = 1;
      #ifdef _PLATFORM_UNIX
      // the Uinx (included the macOS) can't use the IPPROTO_ICMP to create ICMP packet.
      // QAQ 
      if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      {
            perror("Error");
            exit(1);
      }
      #endif

      //time out setting. 10s 
      struct timeval tv;
      tv.tv_sec = 10;
      tv.tv_usec = 0;
      if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      {
            perror("Error");
            close(sockfd);
            exit(0);
      }

      char messge[10], recv[BUFFER_SIZE];
      int addr_len = sizeof(remote_addr);
      memset(messge,0,10);
      memset(&remote_addr,0,sizeof(remote_addr));
      remote_addr.sin_family = AF_INET;
      remote_addr.sin_addr.s_addr = inet_addr("43.254.218.121");
      remote_addr.sin_port = htons(32456);
      IP_packet_t *packet;
      int ret = 0;
      while(ttl < MAX_TTL)
      {
            memset(recv,0,BUFFER_SIZE);
            IP_packet_create(&packet,ttl);
            #ifdef _PLATFORM_UNIX
            if(setsockopt(sockfd,IPPROTO_IP,IP_TTL,&ttl,sizeof(ttl)) < 0)
            {
                  perror("Error");
                  close(sockfd);
                  exit(1); 
            }
            #endif
            if(sendto(sockfd, messge, 10, 0, (struct sockaddr*) &remote_addr,addr_len) < 0)
            {
                  perror("Error");
                  close(sockfd);
                  exit(1);
            }
            if((ret = recvfrom(sockfd, recv, BUFFER_SIZE, 0,(struct sockaddr*) &remote_addr,(socklen_t *)&addr_len)) < 0)
            {
                  perror("Error");
                  if(ret == EWOULDBLOCK || ret == EAGAIN)
                  {
                        printf("time out\n");
                  }
                  printf("%d\n",ret);
            }
            printf("%s\n",recv);
            ttl++;
      }
      
}