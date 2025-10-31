#include <linux/icmp.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <limits.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "icmp.h"
#include "ping.h"

int send_echo(t_pinfo *p) {

  icmphdr_t *icmp;
  struct timeval tv;
  size_t off = 0;

  icmp = (icmphdr_t *)p->buffer;
  gettimeofday(&tv, NULL);
  if (TIMING(p->data_size)) {
    memcpy(icmp->icmp_data, &tv, sizeof(tv));
    off += sizeof(tv);
  }
  if (opt_vals.data)
    memcpy(icmp->icmp_data + off, opt_vals.data,
           off ? p->data_size - off : p->data_size);
  return ping_xmit(p);
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static void tvsub(struct timeval *out, struct timeval *in) {
  if ((out->tv_usec -= in->tv_usec) < 0) {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

void print_echo(int dupflag, struct sockaddr_in *from, struct ip *ip,
                icmphdr_t *icmp, unsigned int datalen) {
  unsigned int hlen;
  struct timeval tv;
  int timing = 0;
  double triptime = 0.0;

  gettimeofday(&tv, NULL);

  /* Length of IP header */
  hlen = ip->ip_hl << 2;

  /* Length of ICMP header+payload */
  datalen -= hlen;

  /* Do timing */
  if (TIMING(datalen - 8)) {
    struct timeval tv1, *tp;

    timing++;
    tp = (struct timeval *)icmp->icmp_data;

    /* Avoid unaligned data: */
    memcpy(&tv1, tp, sizeof(tv1));
    tvsub(&tv, &tv1);

    triptime = ((double)tv.tv_sec) * 1000.0 + ((double)tv.tv_usec) / 1000.0;
    stat.tsum += triptime;
    stat.tsumsq += triptime * triptime;
    if (triptime < stat.tmin)
      stat.tmin = triptime;
    if (triptime > stat.tmax)
      stat.tmax = triptime;
  }

  if (opts & OPT_QUIET)
    return;
  if (opts & OPT_FLOOD) {
    putchar('\b');
    return;
  }

  printf("%d bytes from %s: icmp_seq=%u", datalen,
         inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr), icmp->icmp_seq);
  printf(" ttl=%d", ip->ip_ttl);
  if (timing)
    printf(" time=%.3f ms", triptime);
  if (dupflag)
    printf(" (DUP!)");

  printf("\n");
}

static char *ipaddr2str(struct in_addr ina) {
  struct hostent *hp;

  if (opts & OPT_NUMERIC || !(hp = gethostbyaddr((char *)&ina, 4, AF_INET))) {
    char *s = strdup(inet_ntoa(ina));
    if (!s)
      goto err;
    return s;
  } else {
    char *ipstr = inet_ntoa(ina);
    int len = strlen(hp->h_name) + 1;

    if (ipstr)
      len += strlen(ipstr) + 3; /* a pair of parentheses and a space */

    char *buf = malloc(len);
    if (!buf)
      goto err;
    if (ipstr)
      snprintf(buf, len, "%s (%s)", hp->h_name, ipstr);
    else
      snprintf(buf, len, "%s", hp->h_name);
    return buf;
  }
err:
  perror("ipaddr2str conversion");
  return NULL;
}

#define NITEMS(a) sizeof(a) / sizeof((a)[0])

struct icmp_diag {
  int type;
  char *text;
  void (*fun)(icmphdr_t *, void *data);
  void *data;
};

struct icmp_code_descr {
  int type;
  int code;
  char *diag;
} icmp_code_descr[] = {
    {ICMP_DEST_UNREACH, ICMP_NET_UNREACH, "Destination Net Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, "Destination Host Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, "Destination Protocol Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, "Destination Port Unreachable"},
    {ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, "Fragmentation needed and DF set"},
    {ICMP_DEST_UNREACH, ICMP_SR_FAILED, "Source Route Failed"},
    {ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, "Network Unknown"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNKNOWN, "Host Unknown"},
    {ICMP_DEST_UNREACH, ICMP_HOST_ISOLATED, "Host Isolated"},
    {ICMP_DEST_UNREACH, ICMP_NET_UNR_TOS,
     "Destination Network Unreachable At This TOS"},
    {ICMP_DEST_UNREACH, ICMP_HOST_UNR_TOS,
     "Destination Host Unreachable At This TOS"},
    {ICMP_DEST_UNREACH, ICMP_PKT_FILTERED, "Packet Filtered"},
    {ICMP_DEST_UNREACH, ICMP_PREC_VIOLATION, "Precedence Violation"},
    {ICMP_DEST_UNREACH, ICMP_PREC_CUTOFF, "Precedence Cutoff"},
    {ICMP_REDIRECT, ICMP_REDIR_NET, "Redirect Network"},
    {ICMP_REDIRECT, ICMP_REDIR_HOST, "Redirect Host"},
    {ICMP_REDIRECT, ICMP_REDIR_NETTOS, "Redirect Type of Service and Network"},
    {ICMP_REDIRECT, ICMP_REDIR_HOSTTOS, "Redirect Type of Service and Host"},
    {ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, "Time to live exceeded"},
    {ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, "Frag reassembly time exceeded"}};

static void print_icmp_code(int type, int code, char *prefix) {
  struct icmp_code_descr *p;

  for (p = icmp_code_descr; p < icmp_code_descr + NITEMS(icmp_code_descr); p++)
    if (p->type == type && p->code == code) {
      printf("%s\n", p->diag);
      return;
    }

  printf("%s, Unknown Code: %d\n", prefix, code);
}

static void print_ip_header(struct ip *ip) {
  int hlen;
  unsigned char *cp;

  hlen = ip->ip_hl << 2;
  cp = (unsigned char *)ip + 20; /* point to options */

  printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
  printf(" %1x  %1x  %02x %04x %04x", ip->ip_v, ip->ip_hl, ip->ip_tos,
         ip->ip_len, ip->ip_id);
  printf("   %1x %04x", ((ip->ip_off) & 0xe000) >> 13, (ip->ip_off) & 0x1fff);
  printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p, ip->ip_sum);
  printf(" %s ", inet_ntoa(*((struct in_addr *)&ip->ip_src)));
  printf(" %s ", inet_ntoa(*((struct in_addr *)&ip->ip_dst)));
  while (hlen-- > 20)
    printf("%02x", *cp++);

  printf("\n");
}

void print_ip_data(icmphdr_t *icmp, void *data __attribute__((unused))) {
  int hlen;
  unsigned char *cp;
  struct ip *ip = &icmp->icmp_ip;

  if (!(opts & OPT_VERBOSE))
    return;

  print_ip_header(ip);

  hlen = ip->ip_hl << 2;
  cp = (unsigned char *)ip + hlen;

  if (ip->ip_p == 6)
    printf("TCP: from port %u, to port %u (decimal)\n", (*cp * 256 + *(cp + 1)),
           (*(cp + 2) * 256 + *(cp + 3)));
  else if (ip->ip_p == 17)
    printf("UDP: from port %u, to port %u (decimal)\n", (*cp * 256 + *(cp + 1)),
           (*(cp + 2) * 256 + *(cp + 3)));
}

static void print_icmp(icmphdr_t *icmp, void *data) {
  print_icmp_code(icmp->icmp_type, icmp->icmp_code, data);
  print_ip_data(icmp, NULL);
}

static void print_parameterprob(icmphdr_t *icmp, void *data) {
  printf("Parameter problem: IP address = %s\n", inet_ntoa(icmp->icmp_gwaddr));
  print_ip_data(icmp, data);
}

struct icmp_diag icmp_diag[] = {
    {ICMP_ECHOREPLY, "Echo Reply", NULL, NULL},
    {ICMP_DEST_UNREACH, NULL, print_icmp, "Dest Unreachable"},
    {ICMP_SOURCE_QUENCH, "Source Quench", print_ip_data, NULL},
    {ICMP_REDIRECT, NULL, print_icmp, "Redirect"},
    {ICMP_ECHO, "Echo Request", NULL, NULL},
    {ICMP_TIME_EXCEEDED, NULL, print_icmp, "Time exceeded"},
    {ICMP_PARAMETERPROB, NULL, print_parameterprob, NULL},
    {ICMP_TIMESTAMP, "Timestamp", NULL, NULL},
    {ICMP_TIMESTAMPREPLY, "Timestamp Reply", NULL, NULL},
    {ICMP_INFO_REQUEST, "Information Request", NULL, NULL},
};

void print_icmp_header(struct sockaddr_in *from, struct ip *ip, icmphdr_t *icmp,
                       unsigned int datalen) {
  unsigned int hlen;
  char *s;
  struct icmp_diag *p;

  /* Length of the IP header */
  hlen = ip->ip_hl << 2;

  printf("%d bytes from %s: ", datalen - hlen, s = ipaddr2str(from->sin_addr));
  free(s);

  for (p = icmp_diag; p < icmp_diag + NITEMS(icmp_diag); p++) {
    if (p->type == icmp->icmp_type) {
      if (p->text)
        printf("%s\n", p->text);
      if (p->fun)
        p->fun(icmp, p->data);
      return;
    }
  }
  printf("Bad ICMP type: %d\n", icmp->icmp_type);
}
