#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
/*#include <netinet/ip_icmp.h> -- deliberately not including this */
#include <arpa/inet.h>

#include "icmp.h"

int icmp_generic_encode(unsigned char *buffer, size_t bufsize, int type,
                        int ident, int seqno) {
  icmphdr_t *icmp;

  if (bufsize < 8)
    return -1;
  icmp = (icmphdr_t *)buffer;
  icmp->icmp_type = type;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_seq = seqno;
  icmp->icmp_id = ident;

  icmp->icmp_cksum = icmp_cksum(buffer, bufsize);
  return 0;
}

int icmp_generic_decode(unsigned char *buffer, size_t bufsize, struct ip **ipp,
                        icmphdr_t **icmpp) {
  size_t hlen;
  unsigned short cksum;
  struct ip *ip;
  icmphdr_t *icmp;

  /* IP header */
  ip = (struct ip *)buffer;
  hlen = ip->ip_hl << 2;
  if (bufsize < hlen + ICMP_MINLEN)
    return -1;

  /* ICMP header */
  icmp = (icmphdr_t *)(buffer + hlen);

  /* Prepare return values */
  *ipp = ip;
  *icmpp = icmp;

  /* Recompute checksum */
  cksum = icmp->icmp_cksum;
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = icmp_cksum((unsigned char *)icmp, bufsize - hlen);
  if (icmp->icmp_cksum != cksum)
    return 1;
  return 0;
}

int icmp_echo_encode(unsigned char *buffer, size_t bufsize, int ident,
                     int seqno) {
  return icmp_generic_encode(buffer, bufsize, ICMP_ECHO, ident, seqno);
}

int icmp_echo_decode(unsigned char *buffer, size_t bufsize, struct ip **ipp,
                     icmphdr_t **icmpp) {
  return icmp_generic_decode(buffer, bufsize, ipp, icmpp);
}

unsigned short icmp_cksum(unsigned char *addr, int len) {
  register int sum = 0;
  unsigned short answer = 0;
  unsigned short *wp;

  for (wp = (unsigned short *)addr; len > 1; wp++, len -= 2)
    sum += *wp;

  /* Take in an odd byte if present */
  if (len == 1) {
    *(unsigned char *)&answer = *(unsigned char *)wp;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff); /* add high 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return answer;
}
