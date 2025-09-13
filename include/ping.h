//
// Created by youpaw on 31/01/25.
//

#ifndef PING_H
#define PING_H

#include "icmp.h"
#include <netinet/in.h>
#include <stddef.h>
#include <time.h>
#include <netinet/ip.h>

#define OPT_VERBOSE     0x001
#define OPT_FLOOD       0x002
#define OPT_NUMERIC     0x004
#define OPT_QUIET       0x008

#define DFLT_INTVL 1000     /* default interval ms */

#define DATA_SIZE 56        /* default data size */
#define CKTAB_SIZE 128

#define TIMING(s)  ((s) >= sizeof(struct timeval))

#define CK_BIT(p,bit)   (p)->cktab[(bit)>>3]	/* byte in ck array */
#define CK_IND(p,bit)   (bit % (8 * p->cktab_size))
#define CK_MASK(bit)    (1 << ((bit) & 0x07))

#define CKTAB_SET(p,bit)  (CK_BIT(p,CK_IND(p,bit)) |= CK_MASK(CK_IND(p,bit)))
#define CKTAB_CLR(p,bit)  (CK_BIT(p,CK_IND(p,bit)) &= ~CK_MASK(CK_IND(p,bit)))
#define CKTAB_TST(p,bit)	(CK_BIT(p,CK_IND(p,bit)) & CK_MASK(CK_IND(p,bit)))

extern size_t opts;

typedef struct ping_opt
{
    int socket_type;                /* Socket type */
    unsigned char *data;            /* Icmp data */
	size_t data_size;				/* Size of data */
	size_t count;					/* Number of packets to send */
	size_t interval;				/* Number of ms to wait between sending pkts */
	uint linger;					/* Number of ms to linger before receiving last packet */
	uint timeout;					/* Runner timeout in seconds */
    uint preload;                   /* Number of packets to preload */
} t_popt;

extern t_popt opt_vals;

typedef struct ping_stat
{
	double tmin;                  /* minimum round trip time */
	double tmax;                  /* maximum round trip time */
	double tsum;                  /* sum of all times, for doing average */
	double tsumsq;                /* sum of all times squared, for std. dev. */
} t_pstat;

extern t_pstat stat;

typedef struct ping_info
{
	int fd;							/* Raw socket descriptor */
	int id;							/* Our identifier */
	/* Runtime info */
	char *cktab;
    size_t cktab_size;

	unsigned char *buffer;         /* I/O buffer */
    size_t buffer_size;
	char *hostname;					/* Printable hostname */
	struct sockaddr_in dst;		/* whom to ping */
	struct sockaddr_in src;

	struct timespec start_time;		/* Start time */
	size_t num_xmit;        /* Number of packets transmitted */
	size_t num_recv;        /* Number of packets received */
	size_t num_rept;        /* Number of duplicates received */
} t_pinfo;

int ping_init(t_pinfo *);
int ping_recv(t_pinfo *);
int ping_xmit(t_pinfo *);
int set_dest(t_pinfo *, const char *);

int exec(t_pinfo *);

int send_echo(t_pinfo *);
int print_echo(int dup, struct sockaddr_in *dst, struct sockaddr_in *src, \
               struct ip *, icmphdr_t *, int datalen);
void print_icmp_header(struct sockaddr_in *dst, struct sockaddr_in *src, \
                      struct ip *, icmphdr_t *, int datalen);

#endif //PING_H
