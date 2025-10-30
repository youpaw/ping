//
// Created by youpaw on 09/02/25.
//

#include "icmp.h"
#include "ping.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int create_socket(void) {
  int fd;
  struct protoent *proto;

  proto = getprotobyname("icmp");
  if (!proto) {
    fprintf(stderr, "ping: unknown protocol icmp.\n");
    return -1;
  }
  fd = socket(AF_INET, SOCK_RAW, proto->p_proto);
  if (fd < 0) {
    if (errno == EPERM || errno == EACCES)
      fprintf(stderr, "ping: Lacking privilege for icmp socket.\n");
    fprintf(stderr, "ping: %s\n", strerror(errno));
  }
  return fd;
}

int ping_init(t_pinfo *p) {
  memset(p, 0, sizeof(*p));
  if ((p->fd = create_socket()) < 0)
    return -1;
  p->id = getpid() & 0xFFFF;
  p->cktab_size = CKTAB_SIZE;
  if (!(p->cktab = malloc(CKTAB_SIZE)))
    return -1;
  memset(p->cktab, 0, p->cktab_size);
  p->packet_size = opt_vals.data_size;
  p->buffer = malloc(BUFFER_SIZE(p));
  if (!p->buffer)
    return -1;
  clock_gettime(CLOCK_MONOTONIC, &p->start_time);
  return 0;
}

int ping_xmit(t_pinfo *p) {
  int ret;
  size_t buflen = p->packet_size + 8;

  /* Mark sequence number as sent */
  CKTAB_CLR(p, p->num_xmit);

  /* Encode ICMP header */
  icmp_echo_encode(p->buffer, buflen, p->id, p->num_xmit);

  ret = sendto(p->fd, (char *)p->buffer, buflen, 0,
               (struct sockaddr *)&p->dst, sizeof(struct sockaddr_in));
  if (ret < 0)
    return -1;
  else {
    p->num_xmit++;
    if (ret != buflen)
      printf("ping: wrote %s %zu chars, ret=%d\n", p->hostname, p->packet_size,
             ret);
  }
  return 0;
}

int ping_recv(t_pinfo *p) {
  socklen_t fromlen = sizeof(p->dst);
  int n, rc;
  icmphdr_t *icmp;
  struct ip *ip;
  int dupflag;

  n = recvfrom(p->fd, (char *)p->buffer, BUFFER_SIZE(p), 0,
               (struct sockaddr *)&p->dst, &fromlen);
  if (n < 0)
    return -1;

  rc = icmp_generic_decode(p->buffer, n, &ip, &icmp);
  if (rc < 0) {
    /*FIXME: conditional */
    fprintf(stderr, "packet too short (%d bytes) from %s\n", n,
            inet_ntoa(p->dst.sin_addr));
    return -1;
  }
  switch (icmp->icmp_type) {
  case ICMP_ECHOREPLY:

    if (icmp->icmp_id != p->id)
      return -1;

    if (rc)
      fprintf(stderr, "checksum mismatch from %s\n",
              inet_ntoa(p->src.sin_addr));

    p->num_recv++;
    if (CKTAB_TST(p, icmp->icmp_seq)) {
      p->num_rept++;
      p->num_recv--;
      dupflag = 1;
    } else {
      CKTAB_SET(p, icmp->icmp_seq);
      dupflag = 0;
    }
    print_echo(dupflag, &p->dst, &p->src, ip, icmp, n);

  case ICMP_ECHO:
    return -1;
  default:
    print_icmp_header(&p->dst, &p->src, ip, icmp, n);
  }
  return 0;
}

int set_dest(t_pinfo *p, const char *host) {
  struct sockaddr_in *dst = &p->dst;

  dst->sin_family = AF_INET;
  if (inet_aton(host, &dst->sin_addr))
    p->hostname = strdup(host);
  else {
    struct hostent *hp;
    hp = gethostbyname(host);
    if (!hp)
      return 1;

    dst->sin_family = hp->h_addrtype;
    if (hp->h_length > (int)sizeof(dst->sin_addr))
      hp->h_length = sizeof(dst->sin_addr);

    memcpy(&dst->sin_addr, hp->h_addr, hp->h_length);
    p->hostname = strdup(hp->h_name);
  }
  return 0;
}
