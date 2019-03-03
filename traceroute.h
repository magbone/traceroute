#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <time.h>

#if defined(__APPLE__) || defined(linux)/*defined(TRAGET_OS_IPHONE) || defined(TARGET_OS_MAC) */|| defined(__unix__)
#define _PLATFORM_UNIX
#endif

#ifdef _PLATFORM_UNIX
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>  
#elif _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib") 
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
#endif
#include <errno.h>

#ifndef __TRCEROUTE__H__
#define __TRCEROUTE__H__

// default TTL
#define MAX_TTL 56

// buffer size
#define BUFFER_SIZE 2048

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

void IP_packet_create(IP_packet_t **t, u_int8_t ttl);

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

IP_packet_t* ICMP_packet_clip(char *buffer, size_t buffer_size);

int ICMP_packet_create(ICMP_packet_t *packet, char **buffer);

u_int16_t ICMP_packet_checksum(char *s, int len);

void ICMP_packet_new(ICMP_packet_t **packet, u_int8_t type, u_int8_t code);

/* Unix platform */
void traceroute_unix(int argc, char *argv[]);

/* Windows platform */
void traceroute_win(int argc, char *argv[]);

struct traceroute_cmd
{
      char *addr;
      protocols_t protocol;
      u_int8_t ttl;
};

typedef struct traceroute_cmd traceroute_cmd_t;

void traceroute_cmd_new(traceroute_cmd_t ** cpp);

void traceroute_cmd(int argc, char *argv[]);

int traceroute_isrecv(u_int8_t *op, char * rp);

void traceroute_protocol_udp(traceroute_cmd_t *cp);

void traceroute_protocol_icmp(traceroute_cmd_t *cp);

#endif