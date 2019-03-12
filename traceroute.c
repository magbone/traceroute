#include "traceroute.h"

void IP_packet_create(IP_packet_t **t,  u_int8_t ttl, int (*err_callback)(char *msg))
{
      *t = (IP_packet_t *)malloc(sizeof(IP_packet_t));
      if(t == NULL)
      {
            ERROR_CALLBACK(err_callback, ERROR_MALLOC, NULL);
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

void ICMP_packet_new(ICMP_packet_t **packet, u_int8_t type, u_int8_t code, int (*err_callback)(char *msg))
{
      *packet = (ICMP_packet_t *)malloc(sizeof(packet));
      if((*packet) == NULL)
      {
            ERROR_CALLBACK(err_callback, ERROR_MALLOC, NULL);
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
            temp_check_sum[i] = (s[j] << 8) + (ODD_EVEN(s, j + 1, len) & 0xff);
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

IP_packet_t* ICMP_packet_clip(char *buffer, size_t buffer_size, int (*err_callback)(char *err_msg))
{
      IP_packet_t *packet;
      packet = (IP_packet_t *)malloc(sizeof(IP_packet_t));
      if(packet == NULL) 
      {
            ERROR_CALLBACK(err_callback, ERROR_MALLOC, NULL);
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
      char remote_addr[4] = { buffer[16], buffer[17], buffer[18], buffer[19]};
      packet->remote_addr = (u_int8_t *)remote_addr;

      //ICMP protocol
      ICMP_packet_t *icmp;
      icmp = (ICMP_packet_t *)malloc(sizeof(ICMP_packet_t));
      if(icmp == NULL)
      {
            ERROR_CALLBACK(err_callback, ERROR_MALLOC, NULL);
            exit(1);
      }

      icmp->type = buffer[20];
      icmp->code = buffer[21];

      return packet;
}


void traceroute_protocol_udp(traceroute t, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg))
{
      char *address = t.cmd.addr;

      int sendsockfd, recvsockfd;

      struct sockaddr_in send, recv;

      //send socket.
      if((sendsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            exit(1);
      }
      //recv socket.
      if((recvsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            exit(1);
      }
      struct timeval tv;
      tv.tv_sec = 10; //10s time out
      tv.tv_usec = 0;

      //time out setting
      if(setsockopt(recvsockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            close(recvsockfd);
            exit(0);
      }
      
      memset(&send,0,sizeof(send));
      send.sin_family = AF_INET;
      send.sin_addr.s_addr = inet_addr(address);
      send.sin_port = htons(PORT);

      memset(&recv,0,sizeof(recv));
      recv.sin_addr.s_addr = htonl(INADDR_ANY);
      recv.sin_port = htons(PORT);
      recv.sin_family = AF_INET;

      char send_message[64];
      memset(send_message, 0, 64);
      char recv_message[BUFFER_SIZE];

      //bind
      if(bind(recvsockfd, (struct sockaddr *)& recv, sizeof(recv)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            close(recvsockfd);
            exit(0);
      }

      int ttl = 0;
      int ret = 0;
      int addr_len = sizeof(recv);
      long long times[3] = {0ll, 0ll, 0ll};
      int recv_flag = 0;
      while (ttl < t.cmd.ttl)
      {
            ttl++;
            if(setsockopt(sendsockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            {
                  ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
                  close(sendsockfd);
                  exit(1); 
            }
            memset(recv_message,0,BUFFER_SIZE);
            for(int i = 0;i < 3; i++)
            {
                  long long start = getSystemTime();
                  if(sendto(sendsockfd, send_message, 64, 0, (struct sockaddr*) &send,sizeof(send)) < 0)
                  {
                        ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
                        close(sendsockfd);     
                        exit(1);   
                  }
                  
                  if((ret = recvfrom(recvsockfd, recv_message, BUFFER_SIZE, 0,(struct sockaddr*) &recv,(socklen_t *)&addr_len)) < 0)
                  {
                        recv_flag = 1;
                        long long time_out[3] = {0ll};
                        SUCCESS_CALLBACK(success_callback, NULL, time_out, TIME_OUT);
                        break;
                  }
                  long long finished = getSystemTime();
                  times[i] = finished - start;
            }
            if(recv_flag)
            {
                  recv_flag = 0;
                  continue;
            }
            IP_packet_t* recv_packet = ICMP_packet_clip(recv_message, ret, err_callback);
            char src_address[16];
            IP_INTCHAR(src_address, recv_packet->source_addr);
            SUCCESS_CALLBACK(success_callback, src_address, times, OK);
            if(traceroute_isrecv(recv_packet->source_addr, address))
            {
                  SUCCESS_CALLBACK(success_callback, NULL, NULL, FINISHED);
                  break;
            }
            
      }
      close(sendsockfd);
      close(recvsockfd);
      //free(address);
}

void traceroute_protocol_icmp(traceroute t, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg))
{
      
      int sockfd, sockld;
      char *address = t.cmd.addr;
      
      int ttl = 0;
      struct sockaddr_in remote_addr, local_addr;
      if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            return;
      }
      
      if((sockld = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            exit(1);
      }
      
      
      //time out setting. 10s 
      struct timeval tv;
      tv.tv_sec = 10;
      tv.tv_usec = 0;
      if(setsockopt(sockld, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      {
            ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
            close(sockld);
            exit(0);
      }

      
      char* message, recv[BUFFER_SIZE];
      ICMP_packet_t *packet;
      ICMP_packet_new(&packet, ECHO, 0, err_callback);

      int packet_len = ICMP_packet_create(packet, &message);;
      int addr_len = sizeof(local_addr);
      memset(&remote_addr, 0, sizeof(remote_addr));
      remote_addr.sin_family = AF_INET;
      remote_addr.sin_addr.s_addr = inet_addr(address);
      remote_addr.sin_port = htons(0);
      
      memset(&local_addr, 0, sizeof(local_addr));
      local_addr.sin_family = AF_INET;
      local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      local_addr.sin_port = htons(0);
      int ret = 0;
      int recv_flag = 0;
      long long times[3] = {0ll};
      while(ttl < t.cmd.ttl)
      {
            ttl++;
            if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            {
                  ERROR_CALLBACK(err_callback, "Error %s", strerror(errno));
                  close(sockfd);
                  exit(1); 
            }
            for(int i = 0; i < 3; i++)
            {
                  memset(recv,0,BUFFER_SIZE);
                  long long start = getSystemTime();
                  if(sendto(sockfd, message, packet_len, 0, (struct sockaddr*) &remote_addr,addr_len) < 0)
                  {
                        ERROR_CALLBACK(err_callback, "Error: %s", strerror(errno));
                        close(sockfd);     
                        exit(1);         
                  }
                  if((ret = recvfrom(sockld, recv, BUFFER_SIZE, 0,(struct sockaddr*) &local_addr,(socklen_t *)&addr_len)) < 0)
                  {
                        recv_flag = 1;
                        long long time_out[3] = {0ll};
                        SUCCESS_CALLBACK(success_callback, NULL, time_out, TIME_OUT);
                        break;
                  }
                  long long finished = getSystemTime();
                  times[i] = finished - start;
            }
            if(recv_flag)
            {
                  recv_flag = 0;
                  continue;
            }
            IP_packet_t* recv_packet = ICMP_packet_clip(recv, ret, err_callback);
            char src_address[16];
            IP_INTCHAR(src_address, recv_packet->source_addr);
            SUCCESS_CALLBACK(success_callback, src_address, times, OK);
            if(traceroute_isrecv(recv_packet->source_addr, address))
            {
                  SUCCESS_CALLBACK(success_callback, NULL, NULL, FINISHED);
                  break;
            }
            
      }
      close(sockfd);
      close(sockld);
}


int traceroute_isrecv(u_int8_t *op, char * rp)
{
      char str[16];
      sprintf(str, "%d.%d.%d.%d", op[0], op[1], op[2], op[3]);
      return strcmp(str, rp) == 0;
}

void traceroute_error_msg(char **msg, char *s, int len)
{
      *msg = (char *)malloc(sizeof(char) * len);
      if((*msg) == NULL)
      {
            printf("Error: Init failed in error_msg.\n");
            exit(1);
      }
      strcpy(*msg, s);
}

TRACEROUTE_API int traceroute_init(traceroute **tpp, char **err_msg)
{
      //Usage
      *tpp = (traceroute *)malloc(sizeof(traceroute));
      if((*tpp) == NULL)
      {
            traceroute_error_msg(err_msg, ERROR_MALLOC, strlen(ERROR_MALLOC));
            return 0;
      }
      traceroute_conf_t cp;
      //defualt setting
      cp.ttl = MAXTTL;
      cp.packet_size = DATA_SIZE;
      cp.port = PORT;
      (*tpp)->cmd = cp;
      return 1;
}

TRACEROUTE_API int traceroute_run_async(traceroute *tp, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg))
{
      if(tp == NULL)
      {
            if(err_callback != NULL)
                  err_callback("The traceroute is not be null.");
            else
                  exit(1);
            
      }

      traceroute_conf_t conf = tp->cmd; 

      switch (conf.protocol)
      {
            case ICMP:
                  traceroute_protocol_icmp(*tp, success_callback, err_callback);
                  break;
            case UDP:
                  traceroute_protocol_udp(*tp, success_callback, err_callback);
                  break;
            default:
                  ERROR_CALLBACK(err_callback , ERROR_PROTOCOL, NULL);
                  break;
      }
      return 1;
}