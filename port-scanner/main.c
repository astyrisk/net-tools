/**
 * portscanner.c - TCP Port Scanner
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "port_scanner.h"


int main(int argc, char *argv[])

{

  if (argc != 4) {
    printf("Usage: %s <IP> <start_port> <end_port>\n", argv[0]);
    printf("Example: %s 192.168.1.1 1 1000\n", argv[0]);
    return 1;
  }

  const char *ip = argv[1];

  int start_port = atoi(argv[2]);
  int end_port = atoi(argv[3]);


  printf("Scanning %s from port %d to %d...\n", ip, start_port, end_port);


  for (int port = start_port; port <= end_port; port++) {
    int result = scan_port(ip, port);

    if (result == 1) {
      printf("Port %d: OPEN\n", port);
    } else if ( result == 0) {
      printf("Port %d: CLOSED\n", port);
    } else {
      printf("Port %d: ERROR\n", port);
    }

    usleep(10000);
  }

  return 0;
}
