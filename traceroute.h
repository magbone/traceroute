#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
 
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

#ifndef __TRCEROUTE__H__
#define __TRCEROUTE__H__

// default TTL
#define MAX_TTL 56

// buffer size
#define BUFFER_SIZE 1024


#if defined(__APPLE__)/*defined(TRAGET_OS_IPHONE) || defined(TARGET_OS_MAC) */|| defined(__unix__)
#define _PLATFORM_UNIX
#endif

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
      u_int8_t source_addr[4];
      u_int8_t remote_addr[4];
};

typedef struct IP_packet IP_packet_t;

void IP_packet_create(IP_packet_t **t, u_int8_t ttl);



//ICMP packet

struct ICMP_packet
{
      u_int8_t type;
      u_int8_t code;
      u_int16_t checksum;
};


enum ICMP_packet_type{
      DISTINATION_UNREACHABLE = 3,
      TIME_EXCEEDED = 11,
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

void IPCMP_packet_clip(char *buffer,size_t buffer_size);

void traceroute(int argc,char *argv[]);


#endif