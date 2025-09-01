/*
 *
 * http-client: A simple program that connects to a website, requests a page, and prints the result.
 * with HTTPS Support (OpenSSL)
 *
 * - TODO openssl init
 * - TODO resolve hostname
 * - TODO Create a socket
 * - TODO connect socket to a server
 * - TODO SSL handshake
 * - TODO send http get request
 * - TODO Read and Print the Server's Response
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>

void handle_error(const char *msg)
{
  perror(msg);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  if (argc != 2) {
    printf("Usage: %s <http://example.com>\n", argv[0]);
    return 1;
  }

  char *url = argv[1];
  char *protocol = NULL;
  char *hostname = NULL;
  int port = 0; // 80 for http, 443 for https
  char *path = NULL;

  char *protocol_end = strstr(url, "://");
  if (protocol_end == NULL) {
    handle_error("Invalid URL: Missing protocol prefix (://)");
    /*TODO try http and https*/
  }

  size_t protocol_len = protocol_end - url;
  protocol = malloc(protocol_len +1);
  strncpy(protocol, url, protocol_len);
  protocol[protocol_len] = '\0';

  char *host_start = protocol_end + 3;
  char *host_end = host_start;
  while (*host_end != '\0' && *host_end != '/' && *host_end !=':') {
    host_end++;
  }


  size_t hostname_len = host_end - host_start;
  hostname = malloc(hostname_len + 1);
  strncpy(hostname, host_start, hostname_len);
  hostname[hostname_len] = '\0';

  if (*host_end == ':') {
    char *port_start = host_end;
    char *port_end = port_start;
    while (*port_end != '\0' && *port_end != '/') {
      port_end++;
    }
    char port_str[16];
    size_t port_len = port_end - port_start;
    strncpy(port_str, port_start, port_len);
    port_str[port_len] = '\0';
    port = atoi(port_str);

    if (*port_end == '/') {
      path = strdup(port_end);
    } else {
      path = strdup("/");
    }
  } else if (*host_end == '/') {
    path = strdup(host_end);
    port = (strcmp(protocol, "https") == 0) ? 443 : 80;
  } else {
    path = strdup("/");
    port = (strcmp(protocol, "https") == 0) ? 443 : 80;
  }

  /* printf("Protocol: %s\n", protocol); */
  /* printf("Hostname: %s\n", hostname); */
  /* printf("Port: %d\n", port); */
  /* printf("Path: %s\n", path); */

  /* free(protocol); */
  /* free(hostname); */
  /* free(path); */


  /* setup openssl */
  /* SSL_library_init(); */

  /* resolve hostname to an ip */
  struct addrinfo hints, *res, *p;
  int status;
  char ipstr[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(hostname, protocol, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo error %s\n", gai_strerror(status));
    exit(1);
  }

  for (p = res; p != NULL; p = p->ai_next) {
    void *addr;
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
    addr = &(ipv4->sin_addr);

    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    printf("IP address: %s\n", ipstr);
  }

  freeaddrinfo(res);

  return 0;
}
