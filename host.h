#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>  

#include <errno.h>

#define NAME_SERVER_0 "114.114.114.114"
#define DNS_PORT 53
#define BUFFER_SIZE 1024
#define MAX_DOMAIN_LEN 256

#define A  1
#define NS 2
#define MD 3
#define MF 4
#define CNAME 5
#define SOA 6
#define MB 7  
#define MG 8  
#define MR 9  
#define _NULL 10  
#define WKS 11  
#define PTR 12  
#define HINFO 13  
#define MINFO 14  
#define MX 15  
#define TXT 16

#define GET_CLASS(x) (x == 0x0001 ? "IN" : "NULL")


struct host_header
{
      u_int16_t id;
      /**
       * flags:
       * QR: 1bit query(0), response(1)
       * Opcode: 4bits 
       *    0     a standard query (QUERY) 
       *    1     an inverse query (IQUERY)
       *    2     a server status request (STATUS)
       *    3-15  reserved for future
       * AA: 1bit name server is an authority for the domain name in question section (server) 
       * TC: 1bit truncated due to length greater than that permitted on the transmission channel.
       * RD: 1bit If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
       * RA: 1bit dotes whether recusive query is support in this server. (server)
       * Z: 4bit reserve(0).
       * Recode: 4bit the response
       *    0     No error condition.
       *    1     Format error.
       *    2     Server failure.
       *    3     Name error.
       *    4     Not implemented.
       *    5     Refused.
       *    5-16  Reserved.
       **/
      u_int16_t flags;
      u_int16_t qd_count;
      u_int16_t an_count;
      u_int16_t ns_count;
      u_int16_t ar_count;
};

typedef struct host_header host_header_t;

void host_header_create(host_header_t **hpp);

struct host_domain_name
{
      u_int8_t len;
      u_int8_t *splited_name;
};


typedef struct host_domain_name host_domain_name_t;

struct host_domain_name_index
{
      int index;
      char* domain;
      struct host_domain_name_index *next;
};

typedef struct host_domain_name_index host_domain_name_index_t;

void host_domain_name_index_new(host_domain_name_index_t **ipp);

void host_domain_name_index_add(host_domain_name_index_t *ip, int index, char *domain);

void host_domain_name_index_get(host_domain_name_index_t *ip, int index, char **domain);

int host_domain_name_create(char *domain, host_domain_name_t **npp);

struct host_question
{
      /* this is host_domain_name_t size, it don't belong to the packet */
      int host_domain_name_size;

      host_domain_name_t *t;
      u_int8_t end; // 0x00
      u_int16_t q_type;
      u_int16_t q_class;
};
typedef struct host_question host_question_t;

void host_question_create(host_question_t **qpp, char *domain, int type);

int host_query_create(host_header_t *hp, host_question_t *qp, char **buffer);

u_int8_t* host_query_udp(char *buffer, size_t buffer_size);

u_int8_t* host_reply_unpack(char *buffer, int buffer_size);

char* host_domain_strcat(char buffer[][MAX_DOMAIN_LEN], int buffer_size);

int domain_match(char *input);