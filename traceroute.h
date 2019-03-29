#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#define TRACEROUTE_API

#if defined(__APPLE__) || defined(linux)/*defined(TRAGET_OS_IPHONE) || defined(TARGET_OS_MAC) */|| defined(__unix__)
#define _PLATFORM_UNIX
#endif

#ifdef _PLATFORM_UNIX
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <sys/timeb.h>        // needed for time
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>


#include "host.h"

static long long getSystemTime(){
            struct timeb t;
            ftime(&t);
            return 1000 * t.time + t.millitm;
      }
      
#endif
#include <errno.h>

#ifndef __TRCEROUTE__H__
#define __TRCEROUTE__H__

// default TTL
#define MAX_TTL 56

// buffer size
#ifndef BUFFER_SIZE
#define BUFFER_SIZE 2048
#endif

// data default size
#define DATA_SIZE 64

// default port
#define PORT 32455 


#define ODD_EVEN(arr, i, len) ( (i == len) ? 0x00 : arr[i]) // odd octets

// Protocols

enum protocols
{
      ICMP = 0,
      UDP = 1,
      TCP = 2
};

typedef enum protocols protocols_t;
// create IP packet

/* whole packet */
struct IP_packet
{
      u_int8_t version_IPL;
      u_int8_t type_of_service;
      u_int16_t length;
      u_int16_t indentification;
      u_int16_t flags_fragmentOffset;
      u_int8_t ttl; //time to live;
      u_int8_t protocol; //ICMP we set 1;
      u_int16_t header_checksum; //checksum;
      u_int8_t *source_addr; //32bit
      u_int8_t *remote_addr; //32bit
};

typedef struct IP_packet IP_packet_t;

void IP_packet_create(IP_packet_t **t, u_int8_t ttl, int (*err_callback)(char *msg));

//ICMP packet

struct ICMP_packet
{
      u_int8_t type;
      u_int8_t code;
      u_int16_t checksum;
      u_int16_t indentifier;
      u_int16_t squence;
      u_int8_t data[10];
};

enum ICMP_packet_type{
      DISTINATION_UNREACHABLE = 3,
      TIME_TO_EXCEEDED = 11,
      PARAMETER_PROBLEM = 12,
      SOURCE_QUENCH = 4,
      REDIRECT = 5,
      ECHO = 8,
      ECHO_REPLY = 0,
      TIMESTAMP = 13,
      TIMESTAMP_REPLY = 14,
      INFOMATION_REQUEST = 15,
      INFOMATION_REPLY = 16
};

typedef struct ICMP_packet ICMP_packet_t;

struct traceroute_reply
{
      IP_packet_t ip_packet;
      ICMP_packet_t icmp_packet;
};

typedef struct traceroute_reply traceroute_reply_t;

traceroute_reply_t* ICMP_packet_clip(char *buffer, size_t buffer_size, int (*err_callback)(char *err_msg));

int ICMP_packet_create(ICMP_packet_t *packet, char **buffer);

u_int16_t ICMP_packet_checksum(char *s, int len);

void ICMP_packet_new(ICMP_packet_t **packet, u_int8_t type, u_int8_t code, int (*err_callback)(char *msg));

struct traceroute_conf
{
      char* addr;
      protocols_t protocol;
      u_int8_t ttl;
      u_int8_t packet_size;
      u_int16_t port;
};

typedef struct traceroute_conf traceroute_conf_t;

typedef struct
{
      traceroute_conf_t cmd; //cmd
      int sockfd; //send
      int sockld;  //resv
      
}traceroute;

typedef enum _INFO
{
      TIME_OUT = 0,
      FINISHED = 2,
}INFO;

 
INFO get_type(u_int8_t type);


int traceroute_isrecv(u_int8_t *op, char * rp);

void traceroute_protocol_udp(traceroute t, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg));

void traceroute_protocol_icmp(traceroute t, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg));

void traceroute_error_msg(char **msg, char *s, int len);

// APIs
#define ERROR_MALLOC "Error: Init failed."
#define ERROR_PROTOCOL "Error: No such protocol"

char *traceroute_ipaddress(char *address);

#define ERROR_CALLBACK(fuc, msg, args...) \
      do{ \
            if (args == NULL) { fuc(msg); break;}\
            char msg_s[BUFFER_SIZE]; \
            sprintf(msg_s, msg, args);\
       if(fuc != NULL) fuc(msg_s);\
      }while(0)

#define SUCCESS_CALLBACK(fuc, dest, mss, info) \
      do{ \
            if(fuc != NULL) fuc(dest, mss, info);\
      }while(0)

#define IP_INTCHAR(chars, ints) \
      do{ \
            sprintf(chars, "%d.%d.%d.%d", ints[0], ints[1], ints[2], ints[3]);\
      }while(0)

TRACEROUTE_API int traceroute_init(traceroute **tpp,  char **err_msg);

TRACEROUTE_API int traceroute_run_async(traceroute *tp, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg));

TRACEROUTE_API int traceroute_free(traceroute *tp);

#endif