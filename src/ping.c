//
// Created by youpaw on 20/01/25.
//
#include "ping.h"
#include <asm-generic/socket.h>
#include <errno.h>
#include <error.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

size_t opts = 0;
t_popt opt_vals;

// enum {
//   ARG_TTL,
//   ARG_TIMESTAMP,
// };
//
// static struct argp_option argp_options[] = {
//     {"verbose", 'v', NULL, "verbose output"},
//     {"flood", 'f', NULL, "flood ping (root only)"},
//     {"preload", 'l', "NUMBER",
//      "send NUMBER packets as fast as possible "
//      "before falling into normal mode of behavior (root only)"},
//     {"numeric", 'n', NULL, "do not resolve host addresses"},
//     {"timeout", 'w', "N", "stop after N seconds"},
//     {"linger", 'W', "N", "number of seconds to wait for response"},
//     {"pattern", 'p', "PATTERN", "fill ICMP packet with given pattern (hex)"},
//     {"ignore-routing", 'r', NULL,
//      "send directly to a host on an attached "
//      "network"},
//     {"size", 's', "NUMBER", "send NUMBER data octets"},
//     {"tos", 'T', "NUM", "set type of service (TOS) to NUM"},
//     {"ttl", ARG_TTL, "N", "specify N as time-to-live"},
//     {"timestamp", ARG_TIMESTAMP, NULL, "send ICMP_TIMESTAMP packets"},
// };
//
static void print_usage() {
  printf("Usage\n"
         "  ping [options] <destination>\n\n"
         "Options:\n"
         "  <destination>      dns name or ip address\n"
         "  -v                 verbose output\n");
}

static int parse_args(int argc, char *argv[]) {
  int opt;

  opt_vals.interval = DFLT_INTVL;
  opt_vals.data_size = DATA_SIZE;

  while ((opt = getopt(argc, argv, "vh")) != -1) {
    switch (opt) {
    case 'v':
      opts |= OPT_VERBOSE;
      break;
    case 'h':
      print_usage();
      exit(0);
    default:
      print_usage();
      return -1;
    }
  }
  if (optind >= argc) {
    print_usage();
    return -2;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  t_pinfo ping;
  int rc, one = 1;

  memset(&opt_vals, 0, sizeof(opt_vals));
  if ((rc = parse_args(argc, argv)))
    return rc;
  if ((rc = ping_init(&ping)) < 0)
    return rc;
  
  setsockopt(ping.fd, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));

  if (setuid(getuid()) != 0)
    error(EXIT_FAILURE, errno, "setuid");

  if (opt_vals.socket_type != 0)
    setsockopt(ping.fd, SOL_SOCKET, opt_vals.socket_type, &one, sizeof (one));

  if (set_dest(&ping, argv[argc - 1]))
    error(EXIT_FAILURE, 0, "unknown host");

  rc = exec(&ping);
  //ping_reset(&ping);

  // free (ping);
  //	free (data_buffer);
  return rc;
}
