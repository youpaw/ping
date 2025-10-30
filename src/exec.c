//
// Created by youpaw on 09/02/25.
//

#include "ping.h"
#include <errno.h>
#include <memory.h>
#include <poll.h>
#include <printf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>

t_pstat stat;
int volatile stop = 0;

void sig_int(int signal) { stop = 1; }

static int detect_timeout(const struct timespec *start, uint timeout) {
  struct timespec now;

  if (timeout > 0) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t elapsed = now.tv_sec - start->tv_sec;

    if (now.tv_nsec - start->tv_nsec)
      elapsed--;
    if (elapsed >= timeout)
      return 1;
  }
  return 0;
}

static int run(t_pinfo *p) {
  struct pollfd pfd = {.fd = p->fd, .events = POLLIN};
  int intvl = opts & OPT_FLOOD ? 10 : opt_vals.interval;
  size_t cnt = 0;
  int stopping = 0;

  for (uint i = 0; i < opt_vals.preload; i++)
    send_echo(p);

  send_echo(p);
  while (!stop) {
    int rc = poll(&pfd, 1, intvl);

    if (rc < 0) {
      if (errno == EINTR)
        continue;
      perror("poll failed");
      exit(EXIT_FAILURE);
    } else if (rc == 0) {
      if (!opt_vals.count || p->num_xmit < opt_vals.count) {
        send_echo(p);
        if (opts & OPT_FLOOD)
          putchar('.');
        fflush(stdout);
        if (detect_timeout(&p->start_time, opt_vals.timeout))
          break;
      } else if (stopping) {
        break;
      } else {
        stopping = 1;
        intvl = opt_vals.linger;
      }
    } else if (pfd.revents & POLLIN) {
      if (ping_recv(p) == 0)
        cnt++;
      if (detect_timeout(&p->start_time, opt_vals.timeout) ||
          opt_vals.count && cnt >= opt_vals.count)
        break;
    }
  }
  return 0;
}

static double nabs(double a) { return (a < 0) ? -a : a; }

static double nsqrt(double a, double prec) {
  double x0, x1;

  if (a < 0)
    return 0;
  if (a < prec)
    return 0;
  x1 = a / 2;
  do {
    x0 = x1;
    x1 = (x0 + a / x0) / 2;
  } while (nabs(x1 - x0) > prec);

  return x1;
}

static void print_stat(t_pinfo *p) {
  fflush(stdout);
  printf("--- %s ping statistics ---\n", p->hostname);
  printf("%zu packets transmitted, ", p->num_xmit);
  printf("%zu packets received, ", p->num_recv);
  if (p->num_rept)
    printf("+%zu duplicates, ", p->num_rept);
  if (p->num_xmit) {
    if (p->num_recv > p->num_xmit)
      printf("-- somebody is printing forged packets!");
    else
      printf("%d%% packet loss",
             (int)(((p->num_xmit - p->num_recv) * 100) / p->num_xmit));
  }
  printf("\n");
  if (p->num_recv && TIMING(p->packet_size)) {
    double total = p->num_recv + p->num_rept;
    double avg = stat.tsum / total;
    double vari = stat.tsumsq / total - avg * avg;

    printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms",
           stat.tmin, avg, stat.tmax, nsqrt(vari, 0.0005));
  }
  printf("\n");
}

int exec(t_pinfo *p) {
  int rc = 0;

  memset(&stat, 0, sizeof(stat));
  stat.tmin = 999999999.0;

  printf("PING %s (%s): %zu data bytes", p->hostname,
         inet_ntoa(p->dst.sin_addr), p->packet_size);
  if (opts & OPT_VERBOSE)
    printf(", id 0x%04x = %u\n", p->id, p->id);
  printf("\n");

  signal(SIGINT, sig_int);
  rc = run(p);
  print_stat(p);
  return rc;
}
