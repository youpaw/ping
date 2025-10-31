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

#include "icmp.h"
#include "ping.h"

static int create_socket(void) {
  int fd;
  struct protoent *proto;

  proto = getprotobyname("icmp");
  if (!proto) {
    fprintf(stderr, "ft_ping: unknown protocol icmp.\n");
    return -1;
  }
  fd = socket(AF_INET, SOCK_RAW, proto->p_proto);
  if (fd < 0) {
    if (errno == EPERM || errno == EACCES)
      fprintf(stderr, "ft_ping: Lacking privilege for icmp socket.\n");
    fprintf(stderr, "ft_ping: %s\n", strerror(errno));
  }
  return fd;
}

int ping_init(t_pinfo *p) {
  memset(p, 0, sizeof(*p));
  if ((p->fd = create_socket()) < 0)
    return -1;
  p->id = getpid() & 0xFFFF;
  p->data_size = opt_vals.data_size;
  clock_gettime(CLOCK_MONOTONIC, &p->start_time);
  return 0;
}

void ping_reset(t_pinfo *p) {
  free(p->buffer);
  free(p->cktab);
  free(p->hostname);
}

int buffer_init(t_pinfo *p) {

  if (!(p->cktab = malloc(CKTAB_SIZE)))
    goto err;
  memset(p->cktab, 0, CKTAB_SIZE);
  if (!(p->buffer = malloc(BUFFER_SIZE(p))))
    goto err;
  memset(p->buffer, 0, BUFFER_SIZE(p));
  return 0;
err:
  perror("buffer_init failed");
  return -1;
}

int data_init() {
  size_t i = 0;
  unsigned char *p;

  if (!opt_vals.data_size)
    return -1;

  if (!(opt_vals.data = malloc(opt_vals.data_size)))
    goto err;

  if (opt_vals.ptrn_size) {
    for (p = opt_vals.data; p < opt_vals.data + opt_vals.data_size; p++) {
      *p = opt_vals.ptrn[i];
      if (++i >= opt_vals.ptrn_size)
        i = 0;
    }
  } else {
    for (i = 0; i < opt_vals.data_size; i++)
      opt_vals.data[i] = i;
  }
  return 0;
err:
  perror("data_init failed");
  return -1;
}

int ping_xmit(t_pinfo *p) {
  ssize_t ret;
  ssize_t buflen = p->data_size + 8;

  /* Mark sequence number as sent */
  CKTAB_CLR(p, p->num_xmit);

  /* Encode ICMP header */
  icmp_echo_encode(p->buffer, buflen, p->id, p->num_xmit);

  ret = sendto(p->fd, (char *)p->buffer, buflen, 0, (struct sockaddr *)&p->dst,
               sizeof(struct sockaddr_in));
  if (ret < 0)
    return -1;
  else {
    p->num_xmit++;
    if (ret != buflen)
      printf("ping: wrote %s %zu chars, ret=%zd\n", p->hostname, p->data_size,
             ret);
  }
  return 0;
}

static int my_echo_reply(t_pinfo *p, icmphdr_t *icmp) {
  struct ip *orig_ip = &icmp->icmp_ip;
  icmphdr_t *orig_icmp = (icmphdr_t *)(orig_ip + 1);

  return (orig_ip->ip_dst.s_addr == p->dst.sin_addr.s_addr &&
          orig_ip->ip_p == IPPROTO_ICMP && orig_icmp->icmp_type == ICMP_ECHO &&
          orig_icmp->icmp_id == p->id);
}

int ping_recv(t_pinfo *p) {
  socklen_t fromlen = sizeof(p->from);
  int n, rc;
  icmphdr_t *icmp;
  struct ip *ip;
  int dupflag;

  n = recvfrom(p->fd, (char *)p->buffer, BUFFER_SIZE(p), 0,
               (struct sockaddr *)&p->from, &fromlen);
  if (n < 0)
    return -1;

  rc = icmp_generic_decode(p->buffer, n, &ip, &icmp);
  if (rc < 0) {
    /*FIXME: conditional */
    fprintf(stderr, "packet too short (%d bytes) from %s\n", n,
            inet_ntoa(p->from.sin_addr));
    return -1;
  }
  switch (icmp->icmp_type) {
  case ICMP_ECHOREPLY:

    if (icmp->icmp_id != p->id)
      return -1;

    if (rc)
      fprintf(stderr, "checksum mismatch from %s\n",
              inet_ntoa(p->from.sin_addr));

    p->num_recv++;
    if (CKTAB_TST(p, icmp->icmp_seq)) {
      p->num_rept++;
      p->num_recv--;
      dupflag = 1;
    } else {
      CKTAB_SET(p, icmp->icmp_seq);
      dupflag = 0;
    }
    print_echo(dupflag, &p->from, ip, icmp, n);
    break;

  case ICMP_ECHO:
    return -1;
  default:
    if (!my_echo_reply(p, icmp))
      return -1;
    print_icmp_header(&p->from, ip, icmp, n);
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
