#include <stdio.h>      // Standard input/output functions (e.g., printf)
#include <string.h>     // String manipulation functions (e.g., memset)
#include <unistd.h>     // For close() function
#include <sys/socket.h> // Core socket functions and data structures
#include <netinet/in.h> // Internet-specific address structures (e.g., sockaddr_in)
#include <arpa/inet.h>  // Functions for converting IP addresses (e.g., inet_addr)
#include "port_scanner.h" // Include our own header

#define TIMEOUT 2

int scan_port(const char* ip, int port)
{
  int sockfd;
  struct sockaddr_in target;
  struct timeval timeout;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Socket creaton failed");
    return -1;
  }

  timeout.tv_sec = TIMEOUT;
  timeout.tv_usec = 0;

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  target.sin_family = AF_INET;
  target.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &target.sin_addr) <= 0) {
    perror("Invalid address");
    close(sockfd);
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == 0) {
    close(sockfd);
    return 1;
  }

  close(sockfd);

  return 0;
}
