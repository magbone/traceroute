#include "host.h"

void host_header_create(host_header_t **hpp)
{
      *hpp = (host_header_t *)malloc(sizeof(host_header_t));
      if((*hpp) == NULL)
      {
            printf("Error: Init failed\n");
            exit(1);
      }
      (*hpp)->id = (u_int16_t) getpid();
      (*hpp)->flags = 0x0000 /* query */
            + 0x0000 /* standard query */ 
            + 0x0000 /* not truncated */  
            + 0x0100 /* query recurise */ 
            + 0x0000 /* z: reserved(0) */
            + 0x0000 /* record */;
      (*hpp)->qd_count = 0x0001;
      (*hpp)->an_count = 0x0000;
      (*hpp)->ns_count = 0x0000;
      (*hpp)->ar_count = 0x0000;
}

void host_question_create(host_question_t **qpp, char *domain, int type)
{
      *qpp = (host_question_t *)malloc(sizeof(host_question_t));
      if((*qpp) == NULL)
      {
            printf("Error: Init failed\n");
            exit(1);
      }
      host_domain_name_t *np;
      int len = host_domain_name_create(domain, &np);
      (*qpp)->t = np;
      (*qpp)->host_domain_name_size = len;
      (*qpp)->end = 0x00;
      (*qpp)->q_type = type;
      (*qpp)->q_class = 0x0001;
}

int host_domain_name_create(char *domain, host_domain_name_t **npp)
{

      char *domain_names;
      char *domain_arr[128];
      char domain_tmp[strlen(domain)];
      strncpy(domain_tmp, domain, strlen(domain));
      domain_names = strtok(domain_tmp, ".");
      int i = 0;
      while(domain_names)
      {
            domain_arr[i] = domain_names;
            domain_names = strtok(NULL, ".");
            i++;
      }
      
      host_domain_name_t host_domain_name_arr[i];
      for(int j = 0;j < i; j++)
      {
            host_domain_name_arr[j].len = strlen(domain_arr[j]) & 0xff;
            host_domain_name_arr[j].splited_name = (u_int8_t *)domain_arr[j];
      }
      *npp = host_domain_name_arr;
      return i;
}

int host_query_create(host_header_t *hp, host_question_t *qp, char **buffer)
{
      *buffer = (char *)malloc(sizeof(char) * (sizeof(hp) + sizeof(qp)));
      char *buffer_arr = *buffer;
      if (buffer_arr == NULL) {
            printf("Error: Init failed.\n");
            exit(1);
      }
      int index = 0;
      buffer_arr[index++] = ((hp->id) >> 8) & 0xff;
      buffer_arr[index++] = (hp->id) & 0xff;
      buffer_arr[index++] = ((hp->flags) >> 8) & 0xff;
      buffer_arr[index++] = (hp->flags) & 0xff;
      buffer_arr[index++] = ((hp->qd_count) >> 8) & 0xff;
      buffer_arr[index++] = (hp->qd_count) & 0xff;
      buffer_arr[index++] = ((hp->an_count) >> 8) & 0xff;
      buffer_arr[index++] = (hp->an_count) & 0xff;
      buffer_arr[index++] = ((hp->ns_count) >> 8) & 0xff;
      buffer_arr[index++] = (hp->ns_count) & 0xff;
      buffer_arr[index++] = ((hp->ar_count) >> 8) & 0xff;
      buffer_arr[index++] = (hp->ar_count) & 0xff;

      
      for(int i = 0;i < qp->host_domain_name_size;i++)
      {
            buffer_arr[index++] = qp->t[i].len;
            for(int j = 0;j < qp->t[i].len;j++)
            {
                  buffer_arr[index++] = qp->t[i].splited_name[j];
            }
      }
      buffer_arr[index++] = qp->end;
      buffer_arr[index++] = ((qp->q_type) >> 8) & 0xff;
      buffer_arr[index++] = (qp->q_type) & 0xff;
      buffer_arr[index++] = ((qp->q_class) >> 8) & 0xff;
      buffer_arr[index++] = (qp->q_class) & 0xff;
      return index;
}

u_int8_t* host_query_udp(char *buffer, size_t buffer_size)
{
      int sockfd;
      struct sockaddr_in addr;

      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = inet_addr(NAME_SERVER_0);
      addr.sin_port = htons(DNS_PORT);

      if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      {
            perror("Error[1021]");
            exit(1);
      }

      int addr_len = sizeof(addr);
      char recv_msg[BUFFER_SIZE];
      memset(recv_msg, 0, BUFFER_SIZE);
      char *send_msg = buffer;

      //time out setting. 3s 
      struct timeval tv;
      tv.tv_sec = 3;
      tv.tv_usec = 0;
      if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      {
            
            close(sockfd);
            exit(1);
      }

      int ret;
      if(sendto(sockfd, send_msg, buffer_size, 0, (struct sockaddr*) &addr,addr_len) < 0)
      {
            perror("Error");
            close(sockfd);     
            exit(1);   
      }

      if((ret = recvfrom(sockfd, recv_msg, BUFFER_SIZE, 0,(struct sockaddr*) &addr,(socklen_t *)&addr_len)) < 0)
      {
            goto Close; 
      }

      u_int8_t *ip = host_reply_unpack(recv_msg, ret);
      if((ret = recvfrom(sockfd, recv_msg, BUFFER_SIZE, 0,(struct sockaddr*) &addr,(socklen_t *)&addr_len)) < 0)
      {
            goto Close;
      }

      host_reply_unpack(recv_msg, ret);
      Close:
      close(sockfd);
      return ip;
}

u_int8_t* host_reply_unpack(char *buffer, int buffer_size)
{
      int index = 0; 
      u_int8_t *ip_address;
      host_header_t *hp;
      host_header_create(&hp);
      hp->id = ((buffer[0] << 8) & 0xffff) + (buffer[1] & 0x00ff);
      hp->flags = ((buffer[2] << 8) & 0xffff) + (buffer[3] & 0x00ff);
      hp->qd_count = ((buffer[4] << 8) & 0xffff) + (buffer[5] & 0x00ff);
      hp->an_count = ((buffer[6] << 8) & 0xffff) + (buffer[7] & 0x00ff);
      hp->ns_count = ((buffer[8] << 8) & 0xffff) + (buffer[9] & 0x00ff);
      hp->ar_count = ((buffer[10] << 8) & 0xffff) + (buffer[11] & 0x00ff);
      
      index = 12;

      //domain link. the compression.
      host_domain_name_index_t *ip;
      host_domain_name_index_new(&ip);
      //query 
      char name[MAX_DOMAIN_LEN][MAX_DOMAIN_LEN];
      int name_index = index; // record the entire domain offset
      int name_t = 0;
      while((buffer[index++] & 0xff ) != 0x00)
      {
            int len = buffer[--index] & 0xff;
            int this_index = index;
            char sub_domain[len + 1];
            memset(sub_domain, 0, len + 1);
            index++;
            for(int i = 0; i < len; i++)
            {     
                  sub_domain[i] = buffer[index++];
            }
            char* name_temp = name[name_t++];
            strcpy(name_temp, sub_domain);
            if(name_t > 1)
            host_domain_name_index_add(ip, this_index, name_temp);
      }

      char *domain_name = host_domain_strcat(name, name_t);
      host_domain_name_index_add(ip, name_index, domain_name);
      index+=4;

      //answers
      for(int i = 0; i < hp->an_count; i++)
      {
            u_int16_t first_octets = ((buffer[index++] << 8) & 0xff00) - 0xc000;
            int an_name = first_octets + (buffer[index++] & 0x00ff);
            first_octets = (buffer[index++] << 8) & 0xff00;
            u_int16_t type =  first_octets + (buffer[index++] & 0x00ff);
            first_octets = (buffer[index++] << 8) & 0xff00;
            u_int16_t class = first_octets + (buffer[index++] & 0x00ff);
            u_int16_t ttl = ((buffer[index] << 24) & 0xff000000)  + ((buffer[index + 1] << 16) & 0x00ff0000)+ ((buffer[index + 2] << 8) & 0x0000ff00)+ (buffer[index + 3] & 0x000000ff);
            index+=4;

            first_octets = (buffer[index++] <<8) & 0xff00;
            u_int16_t length = first_octets + (buffer[index++] & 0x00ff);
            switch(type)
            {
                  case A:
                  {
                        
                        u_int8_t address[length];
                        for(int j = 0; j < length; j++)
                        {
                              address[j] = (u_int8_t)buffer[index++]; 
                        }
                        char *rel_name;
                        host_domain_name_index_get(ip, an_name, &rel_name);

                        if((ip_address = (u_int8_t *)(malloc(sizeof(u_int8_t) * 4))) == NULL)
                        {
                              printf("Error: Init failed.\n");
                              exit(1);
                        }
                        memcpy(ip_address, address, length);
                        break;
                  }
                  
                  
            }
           
      }

      free(ip);
      return ip_address;
}

void host_domain_name_index_new(host_domain_name_index_t **ipp)
{
      *ipp = (host_domain_name_index_t *)malloc(sizeof(host_domain_name_index_t));
      if((*ipp) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      (*ipp)-> next = NULL;
      (*ipp)-> index = 0x3f3f3f3f;
}

void host_domain_name_index_add(host_domain_name_index_t *ip, int index, char *domain)
{
      host_domain_name_index_t *new_p = (host_domain_name_index_t *)malloc(sizeof(host_domain_name_index_t));

      if(new_p == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      host_domain_name_index_t *ip_tmp = ip;
      while(ip_tmp && ip_tmp->next) 
      {
            if(index == ip_tmp->index) return;
            ip_tmp = ip_tmp->next;
      }
      
      new_p->index = index;
      new_p->domain = domain;
      new_p->next = NULL;
      ip_tmp->next = new_p;
}

void host_domain_name_index_get(host_domain_name_index_t *ip, int index, char **domain)
{
      host_domain_name_index_t* ip_tmp = ip->next;
      
      while(ip_tmp)
      {
            if(ip_tmp->index == index)
            {
                  
                  *domain = ip_tmp->domain;
                  break;
            }
      
            ip_tmp = ip_tmp->next;
      }
}
/**
 * let the string[subdomain] array combine to compete domain
 * 
 * like this:     @param *buffer -> ["www", "example", "com"]
 *                @param buffer_size the buffer length;
 *                @return char* -> ["www.example.com"]
 **/
char* host_domain_strcat(char buffer[][MAX_DOMAIN_LEN], int buffer_size)
{
      char *domain_p;
      if((domain_p = (char *)malloc(sizeof(char) * MAX_DOMAIN_LEN)) == NULL)
      {
            printf("Error: Init failed\n");
            exit(0);
      }
      for(int i = 0;i < buffer_size;i++)
      {
            strcat(domain_p, buffer[i]);
            if((i + 1) < buffer_size) strcat(domain_p, ".");
      }
      return domain_p;
}


int domain_match(char *input)
{
      regex_t reg;
      const char * pattern = "[a-z]|[A-Z]";
      regcomp(&reg, pattern, REG_EXTENDED);

      const size_t nmatch = 1;
      regmatch_t pmatch[1];
      return regexec(&reg, input, nmatch, pmatch,0); 
}