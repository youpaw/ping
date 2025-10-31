#include <asm-generic/socket.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <memory.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ping.h"

#define MAX_DATA_SIZE (65535 - MAXIPLEN - MAXICMPLEN)
#define MAX_PTRN_SIZE 16

size_t opts = 0;
t_popt opt_vals;

static void print_usage() {
  printf("Usage\n"
         "  ft_ping [options] <destination>\n\n"
         "Options:\n"
         "  <destination>      dns name or ip address\n"
         "  -c <count>         stop after <count> replies\n"
         "  -f                 flood ping\n"
         "  -h                 print help and exit\n"
         "  -l <preload>       send <preload> number of packages while waiting "
         "replies\n"
         "  -n                 no dns name resolution\n"
         "  -p <pattern>       contents of padding byte\n"
         "  -q                 quiet output\n"
         "  -r                 send directly to a host on an "
         "attached network\n"
         "  -s <size>          use <size> as number of data bytes to be sent\n"
         "  -t <ttl>           define time to live\n"
         "  -T <tos>           set type of service (TOS)\n"
         "  -v                 verbose output\n"
         "  -w <deadline>      reply wait <deadline> in seconds\n"
         "  -W <timeout>       time to wait for response\n");
}

static size_t decode_pattern(const char *arg, unsigned char *pattern_data) {
  int c, off;
  size_t i;

  for (i = 0; *arg && i < MAX_PTRN_SIZE; i++) {
    if (sscanf(arg, "%2x%n", &c, &off) != 1)
      error(EXIT_FAILURE, 0, "error in pattern near %s", arg);

    arg += off;
    pattern_data[i] = c;
  }
  return i;
}

static size_t validate_arg(const char *arg, size_t max_val, int allow_zero) {
  char *p;
  unsigned long int n;

  n = strtoul(arg, &p, 0);
  if (*p)
    error(EXIT_FAILURE, 0, "invalid value (`%s' near `%s')", arg, p);

  if (n == 0 && !allow_zero)
    error(EXIT_FAILURE, 0, "option value too small: %s", arg);

  if (max_val && n > max_val)
    error(EXIT_FAILURE, 0, "option value too big: %s", arg);

  return n;
}

static int parse_args(int argc, char *argv[]) {
  static unsigned char pattern[MAX_PTRN_SIZE];
  int opt;
  char *endptr;

  opt_vals.interval = DFLT_INTVL;
  opt_vals.data_size = DATA_SIZE;
  opt_vals.ttl = -1;

  while ((opt = getopt(argc, argv, "c:fhl:np:qrs:t:T:vw:W:")) != -1) {
    switch (opt) {
    case 'c':
      opt_vals.count = validate_arg(optarg, INT_MAX, 0);
      break;
    case 'f':
      opts |= OPT_FLOOD;
      break;
    case 'h':
      print_usage();
      exit(0);
    case 'l':
      opt_vals.preload = strtoul(optarg, &endptr, 0);
      if (*endptr || opt_vals.preload > INT_MAX)
        error(EXIT_FAILURE, 0, "invalid preload value (%s)", optarg);
      break;
    case 'n':
      opts |= OPT_NUMERIC;
      break;
    case 'p':
      opt_vals.ptrn_size = decode_pattern(optarg, pattern);
      opt_vals.ptrn = pattern;
      break;
    case 'q':
      opts |= OPT_QUIET;
      break;
    case 'r':
      opt_vals.socket_type |= SO_DONTROUTE;
      break;
    case 's':
      opt_vals.data_size = validate_arg(optarg, MAX_DATA_SIZE, 1);
      break;
    case 't':
      opt_vals.ttl = validate_arg(optarg, 255, 0);
      break;
    case 'T':
      opt_vals.tos = validate_arg(optarg, 255, 1);
      break;
    case 'v':
      opts |= OPT_VERBOSE;
      break;
    case 'w':
      opt_vals.timeout = validate_arg(optarg, INT_MAX, 0);
      break;
    case 'W':
      opt_vals.linger = validate_arg(optarg, INT_MAX, 0);
      break;
    default:
      print_usage();
      return -1;
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "ft_ping: usage error: Destination address required\n");
    return -1;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  t_pinfo ping;
  int rc, one = 1;

  memset(&opt_vals, 0, sizeof(opt_vals));
  if ((rc = parse_args(argc, argv)))
    return rc;
  if ((rc = ping_init(&ping)))
    return rc;

  setsockopt(ping.fd, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));

  if (setuid(getuid()) != 0)
    error(EXIT_FAILURE, errno, "setuid");

  if (opt_vals.socket_type != 0)
    setsockopt(ping.fd, SOL_SOCKET, opt_vals.socket_type, &one, sizeof(one));

  if (opt_vals.ttl > 0)
    if (setsockopt(ping.fd, IPPROTO_IP, IP_TTL, &opt_vals.ttl,
                   sizeof(opt_vals.ttl)) < 0)
      error(0, errno, "setsockopt(IP_TTL)");

  if (opt_vals.tos >= 0)
    if (setsockopt(ping.fd, IPPROTO_IP, IP_TOS, &opt_vals.tos,
                   sizeof(opt_vals.tos)) < 0)
      error(0, errno, "setsockopt(IP_TOS)");

  if (set_dest(&ping, argv[optind]))
    error(EXIT_FAILURE, 0, "unknown host");

  if ((rc = data_init()))
    return rc;
  if (!(rc = buffer_init(&ping)))
    rc = exec(&ping);

  ping_reset(&ping);
  return rc;
}
