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
      (*packet)->indentifier = 0x0100;
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
            temp_check_sum[i] = (s[j] << 8) + s[j + 1];
      }
      int k = 0, sum = 0;

      while(k < temp_len)
      {
            sum += temp_check_sum[k];
            if(sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
            k++;
      }

      return (u_int16_t)~sum;
}

void ICMP_packet_clip(char *buffer, size_t buffer_size)
{
      IP_packet_t *packet;
      packet = (IP_packet_t *)malloc(sizeof(IP_packet_t));
      if(packet == NULL) 
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      //int index = 0;
      packet->version_IPL = buffer[0];
      packet->type_of_service = buffer[1];
      packet->length = (buffer[2] << 8) + (buffer[3] & 0xff);//(buffer[index++] << 8 ) + (buffer[index++]);
      packet->indentification = (buffer[4] << 8) + (buffer[5] & 0xff);
      packet->flags_fragmentOffset = (buffer[6] << 8) + (buffer[7] & 0xff);
      packet->ttl = buffer[8];
      printf("%d\t", packet->ttl);
      packet->protocol = buffer[9];
      packet->header_checksum = (buffer[10] << 8) + (buffer[11] & 0xff);
      char source_addr[4] = { buffer[12], buffer[13], buffer[14], buffer[15]};
      packet->source_addr = (u_int8_t *)source_addr;
      printf("%d.%d.%d.%d\n", packet->source_addr[0], packet->source_addr[1], packet->source_addr[2], packet->source_addr[3]);
      char remote_addr[4] = { buffer[16], buffer[17], buffer[18], buffer[19]};
      packet->source_addr = (u_int8_t *)remote_addr;

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
}
#ifdef _PLATFORM_UNIX
void traceroute_unix(int argc,char *argv[])
{
      //command

      int sockfd;
      

      int ttl = 0;
      struct sockaddr_in remote_addr;
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

      int packet_len = ICMP_packet_create(packet, &message);
      int addr_len = sizeof(remote_addr);
      memset(&remote_addr,0,sizeof(remote_addr));
      remote_addr.sin_family = AF_INET;
      remote_addr.sin_addr.s_addr = inet_addr("43.254.218.121");
      remote_addr.sin_port = htons(32456);

      
      int ret = 0;
      while(ttl < MAX_TTL)
      {
            memset(recv,0,BUFFER_SIZE);
            ttl++;
            if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl)) < 0)
            {
                  perror("Error");
                  close(sockfd);
                  exit(1); 
            }
            if(sendto(sockfd, message, packet_len, 0, (struct sockaddr*) &remote_addr,addr_len) < 0)
            {
                  perror("Error");
                  close(sockfd);
                  exit(1);
            }
            if((ret = recvfrom(sockfd, recv, BUFFER_SIZE, 0,(struct sockaddr*) &remote_addr,(socklen_t *)&addr_len)) < 0)
            {
                  //perror("Error");
                  if(ret == EWOULDBLOCK || ret == EAGAIN)
                  {
                        printf("time out\n");
                  }
            }
            printf("%d\n",ret);
            ICMP_packet_clip(recv, ret);
            sleep(3);
            //break;
      }
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

            printf("%s\n", recv);
            ttl++;
      }
      
}           

#endif