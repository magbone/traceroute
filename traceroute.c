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

int ICMP_packet_create(ICMP_packet_t *packet, char **buffer)
{
      *buffer = (char *)malloc(sizeof(char) * 18);
      char *buffer_arr = *buffer;
      buffer_arr[0] = packet->type;
      buffer_arr[1] = packet->code;
      buffer_arr[2] = (packet->checksum) >> 8;
      buffer_arr[3] = (packet->checksum) & 0xff;
      buffer_arr[4] = (packet->indentifier) >> 8;
      buffer_arr[5] = (packet->indentifier) & 0xff;
      buffer_arr[6] = (packet->squence) >> 8;
      buffer_arr[7] = (packet->squence) & 0xff;

      char *data = (char *)(packet->data);
      for(int i = 0;i < 10;i++)
      {
            buffer_arr[i + 9] = data[i];
      }
      //checksum
      u_int16_t checksum = ICMP_packet_checksum(*buffer, sizeof(buffer));
      buffer_arr[2] = checksum >> 8;
      buffer_arr[3] = checksum & 0xff;
      packet->checksum = checksum;
      return sizeof(buffer);
}

void ICMP_packet_new(ICMP_packet_t **packet, u_int8_t type, u_int8_t code)
{
      *packet = (ICMP_packet_t *)malloc(sizeof(packet));
      if((*packet) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      (*packet)->type = type;
      (*packet)->code = code;
      (*packet)->checksum = 0x0000;
      (*packet)->indentifier = (u_int16_t)getpid();
      (*packet)->squence = 0x0000;
      memset(((*packet)->data), 0, 10);
}

u_int16_t ICMP_packet_checksum(char *s, int len)
{
      int temp_len = len % 2 != 0 ? len / 2 + 1 : len / 2;
      u_int16_t temp_check_sum[temp_len];
      u_int16_t checksum;
      memset(temp_check_sum, 0, temp_len);
      for(int i = 0, j = 0;i < temp_len;i++,j+=2)
      {
            temp_check_sum[i] = (s[j] << 8) + (s[j + 1] & 0xff);
      }
      int k = 0, sum = 0;

      while(k < temp_len)
      {
            sum += temp_check_sum[k];
            k++;
      }
      
      while(sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
      return (u_int16_t)~sum;
}

IP_packet_t* ICMP_packet_clip(char *buffer, size_t buffer_size)
{
      IP_packet_t *packet;
      packet = (IP_packet_t *)malloc(sizeof(IP_packet_t));
      if(packet == NULL) 
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      int index = 0;
      packet->version_IPL = buffer[0];
      packet->type_of_service = buffer[1];
      packet->length = (buffer[2] << 8) + (buffer[3] & 0xff);//(buffer[index++] << 8 ) + (buffer[index++]);
      packet->indentification = (buffer[4] << 8) + (buffer[5] & 0xff);
      packet->flags_fragmentOffset = (buffer[6] << 8) + (buffer[7] & 0xff);
      packet->ttl = buffer[8];
      packet->protocol = buffer[9];
      packet->header_checksum = (buffer[10] << 8) + (buffer[11] & 0xff);
      char source_addr[4] = { buffer[12], buffer[13], buffer[14], buffer[15]};
      packet->source_addr = (u_int8_t *)source_addr;
      printf("%d.%d.%d.%d\t", packet->source_addr[0], packet->source_addr[1], packet->source_addr[2], packet->source_addr[3]);
      char remote_addr[4] = { buffer[16], buffer[17], buffer[18], buffer[19]};
      packet->remote_addr = (u_int8_t *)remote_addr;

      //ICMP protocol
      ICMP_packet_t *icmp;
      icmp = (ICMP_packet_t *)malloc(sizeof(ICMP_packet_t));
      if(icmp == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      icmp->type = buffer[20];
      icmp->code = buffer[21];

      return packet;
}
#ifdef _PLATFORM_UNIX
void traceroute_unix(int argc,char *argv[])
{
      //command
      traceroute_cmd(argc, argv);
}

#elif _WIN32
void traceroute_win(int argc,char *argv[])
{
      WORD socket_version = MAKEWORD(2,2);
      WSADATA data;
      if(WSAStartup(socket_version, &data) != 0)
      {
            printf("Error: Startup error.\n");
            exit(1);
      }

      SOCKET s_client = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
      if(s_client == INVALID_SOCKET)
      {
            printf("Error: Socket create error. Error code: %d.\n", WSAGetLastError());
            exit(1);
      }

      SOCKADDR_IN remote_addr;
      remote_addr.sin_family = AF_INET;
      remote_addr.sin_port = htons(0);
      remote_addr.sin_addr.S_un.S_addr = inet_addr("43.254.218.121");

      char* message, recv[BUFFER_SIZE];
      ICMP_packet_t *packet;
      ICMP_packet_new(&packet, ECHO, 0);

      int packet_len = ICMP_packet_create(packet, &message);
      
      if(connect(s_client, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == SOCKET_ERROR)
      {
            
            printf("Error: Connect failed.\n");
            closesocket(s_client);
            exit(1);
      }

      int ttl = 1;
      int ret;
      int len = sizeof(remote_addr);
      
      //char nochecksum = 1;
      //setsockopt(s_client, IPPROTO_UDP, UDP_NOCHECKSUM, &nochecksum, sizeof(nochecksum));
      
      while(ttl <= MAX_TTL)
      {
            memset(recv, 0, BUFFER_SIZE);
            
            if(setsockopt(s_client, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl)) == SOCKET_ERROR)
            {
                  printf("Error: Socket option set error.\n");
                  closesocket(s_client);
                  exit(1);
            }
            if(sendto(s_client, message, packet_len, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
            {
                  printf("Error: Send error. Error code: %d\n", WSAGetLastError());
                  closesocket(s_client);
                  exit(1);
            }
            
            if((ret = recvfrom(s_client, recv, BUFFER_SIZE, 0, (struct sockaddr *)&remote_addr, (socklen_t *)&len)) < 0)
            {
                  printf("Error: Receive error. Error code: %d\n",  WSAGetLastError());
                  closesocket(s_client);
                  exit(1);
            }
            ICMP_packet_clip(recv, ret);
            //printf("%s\n", recv);
            ttl++;
      }
      
}           

#endif

void traceroute_cmd(int argc, char *argv[])
{
      
      //Usage
      traceroute_cmd_t *cp;
      traceroute_cmd_new(&cp);
      cp->ttl = MAXTTL;
      if(argc == 1)
      {
            printf("traceroute [-P][protocol] [-t][ttl] [host]\nUsage:\n-P\tprotocol. ICMP, UDP, TCP argument\n-t\ttime to live.\n");
            return;
      }
      for(int i = 1; i < argc;i++)
      {
            char *argment = argv[i];
            if(strcmp("-P", argment) == 0)
            {
                  i++;
                  if(strcmp("ICMP", argv[i]) == 0)
                  {
                        cp->protocol = ICMP;
                  }
                  else if(strcmp("UDP", argv[i]) == 0)
                  {
                        cp->protocol = UDP;
                  }
                  else if(strcmp("TCP", argv[i]) == 0)
                  {
                        cp->protocol = TCP;
                  }
                  else{
                        printf("Error: Invalid argument -p.\n");
                        exit(1);
                  }
            }
            else if (strcmp("-t", argment) == 0) 
            {
                  i++;
                  cp->ttl = (u_int8_t)atoi(argv[i]);
            }
            
            else
            {
                 cp->addr = argv[i];
            }
      }
      printf("traceroute to the %s and heartbeat packet %d times, packet size total 64 bytes.\n", cp->addr, cp->ttl);
      if(cp->protocol == UDP)
      {
            traceroute_protocol_udp(cp);
      }
      else if(cp->protocol == ICMP)
      {
            traceroute_protocol_icmp(cp);
      }
      
}

void traceroute_protocol_udp(traceroute_cmd_t *cp)
{
      if(cp == NULL)
      {
            printf("Error: NULL pointer error.\n");
            exit(0);
      }
      char *address = cp->addr;

      int sendsockfd, recvsockfd;

      struct sockaddr_in send, recv;

      //send socket.
      if((sendsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      {
            perror("Error[1021]");
            exit(1);
      }
      //recv socket.
      if((recvsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      {
            perror("Error[1022]");
            exit(1);
      }
      struct timeval tv;
      tv.tv_sec = 10; //10s time out
      tv.tv_usec = 0;

      //time out setting
      if(setsockopt(recvsockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      {
            perror("Error[1023]");
            close(recvsockfd);
            exit(0);
      }
      
      memset(&send,0,sizeof(send));
      send.sin_family = AF_INET;
      send.sin_addr.s_addr = inet_addr(address);
      send.sin_port = htons(32455);

      memset(&recv,0,sizeof(recv));
      recv.sin_addr.s_addr = htonl(INADDR_ANY);
      recv.sin_port = htons(32455);
      recv.sin_family = AF_INET;

      char send_message[64];
      memset(send_message, 0, 64);
      char recv_message[BUFFER_SIZE];

      //bind
      if(bind(recvsockfd, (struct sockaddr *)& recv, sizeof(recv)) < 0)
      {
            perror("Error[1024]");
            close(recvsockfd);
            exit(0);
      }

      int ttl = 1;
      int ret = 0;
      int addr_len = sizeof(recv);
      clock_t start, finshed;
      while (ttl < cp->ttl)
      {
            start = clock();
            if(setsockopt(sendsockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            {
                  perror("Error[1025]");
                  close(sendsockfd);
                  exit(1); 
            }
          
            memset(recv_message,0,BUFFER_SIZE);
            if(sendto(sendsockfd, send_message, 64, 0, (struct sockaddr*) &send,sizeof(send)) < 0)
            {
                  perror("Error[1026]");
                  close(sendsockfd);     
                  exit(1);   
            }
            
            if((ret = recvfrom(recvsockfd, recv_message, BUFFER_SIZE, 0,(struct sockaddr*) &recv,(socklen_t *)&addr_len)) < 0)
            {
                  printf("*.*.*.*\t*\n");
                  continue;
            }
            finshed = clock();
            
            IP_packet_t* recv_packet = ICMP_packet_clip(recv_message, ret);
            printf("%ldms\n", (finshed - start));
            if(traceroute_isrecv(recv_packet->source_addr, address))
            {
                  printf("The route arrive the distination %s, traceroute finshed.\n", address);
                  break;
            }
            ttl++;
            sleep(3);
      }
      close(sendsockfd);
      close(recvsockfd);
      //free(address);
}

void traceroute_protocol_icmp(traceroute_cmd_t *cp)
{
      
      int sockfd;

      int ttl = 0;
      struct sockaddr_in remote_addr;
      // ICMP
      // the Uinx (included the macOS) can't use the IPPROTO_ICMP to create ICMP packet.
      // QAQ 
      // ICMP model
      if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      {
            perror("Error");
            exit(1);
      }
      

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

      
      char* message, recv[BUFFER_SIZE];
      ICMP_packet_t *packet;
      ICMP_packet_new(&packet, ECHO, 0);

      int packet_len = ICMP_packet_create(packet, &message);;
      int addr_len = sizeof(remote_addr);
      memset(&remote_addr,0,sizeof(remote_addr));
      remote_addr.sin_family = AF_INET;
      remote_addr.sin_addr.s_addr = inet_addr("43.254.218.121");
      remote_addr.sin_port = htons(0);
      
      int ret = 0;
      while(ttl < MAX_TTL)
      {
            ttl++;
            if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            {
                  perror("Error");
                  close(sockfd);
                  exit(1); 
            }
          
            memset(recv,0,BUFFER_SIZE);
            for(int i = 0;i < 3;i++)
            {
                  if(sendto(sockfd, message, packet_len, 0, (struct sockaddr*) &remote_addr,addr_len) < 0)
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
                  }
                  ICMP_packet_clip(recv, ret);
            }
            
            sleep(10);
            
      }
}

void traceroute_cmd_new(traceroute_cmd_t **cp)
{
      *cp = (traceroute_cmd_t *)malloc(sizeof(traceroute_cmd_t));
      if((*cp) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
}

int traceroute_isrecv(u_int8_t *op, char * rp)
{
      char str[15];
      sprintf(str, "%d.%d.%d.%d", op[0], op[1], op[2], op[3]);
      return strcmp(str, rp) == 0;
}