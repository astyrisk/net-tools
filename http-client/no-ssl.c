/*
 *
 * http-client: A simple program that connects to a website, requests a page, and prints the result.
 * no HTTPS Support
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct {
  char *protocol;
  char *hostname;
  int port;
  char *path;
} ParsedUrl;

ParsedUrl *parse_url(const char *url)
{
  ParsedUrl *parsed_url = malloc(sizeof(ParsedUrl));
  if (parsed_url == NULL) {
    perror("Failed to allocate memory for parsed url");
    return NULL;
  }

  parsed_url->protocol = NULL;
  parsed_url->hostname = NULL;
  parsed_url->port = 80;
  parsed_url->path = NULL;

  char *url_copy = strdup(url);
  if (url_copy == NULL) {
    perror("Failed to duplicate the url");
    free(parsed_url);
    return NULL;
  }
  char *p = url_copy;
  char *protocol_end = strstr(p, "://");
  if (protocol_end != NULL) {
    size_t protocol_len = protocol_end - p;
    parsed_url->protocol = strndup(p, protocol_len);
    p = protocol_end + 3;
  } else {
    parsed_url->protocol = strdup("http");
  }
  char *path_start = strchr(p, '/');
  char *port_start = strchr(p, ':');
  char *host_end = NULL;

  if (port_start != NULL && (path_start == NULL || port_start < path_start)) {
    host_end = port_start;
  } else if (path_start != NULL) {
    host_end = path_start;
  } else {
    host_end = p + strlen(p);
  }

  if (host_end == NULL) {
    fprintf(stderr, "Invalid URL: Cannot determine hostname.\n");
    free(url_copy);
    free(parsed_url->protocol);
    free(parsed_url);
    return NULL;
  }

  size_t host_len = host_end - p;
  parsed_url->hostname = strndup(p, host_len);
  if (parsed_url->hostname == NULL) {
    perror("Failed to allocate memory for hostname");
    free(url_copy);
    free(parsed_url->protocol);
    free(parsed_url);
    return NULL;
  }

  p = host_end;
  if (port_start != NULL && port_start == host_end) {
    char *port_end = NULL;
    if (path_start != NULL) {
      port_end = path_start;
    } else {
      port_end = p + strlen(p);
    }

    char port_str[10];
    size_t port_len = port_end - (port_start + 1);
    if (port_len > sizeof(port_str) - 1) {
      fprintf(stderr, "Port number too long.\n");
      free(url_copy);
      free(parsed_url->protocol);
      free(parsed_url->hostname);
      free(parsed_url);
      return NULL;
    }
    strncpy(port_str, port_start + 1, port_len);
    port_str[port_len] = '\0';
    parsed_url->port = atoi(port_str);
    p = port_end;
  }

  if (path_start != NULL && path_start == p) {
    parsed_url->path = strdup(p);
  } else {
    parsed_url->path = strdup("/");
  }

  return parsed_url;
}

void free_parsed_url(ParsedUrl *url)
{
  if (url == NULL) {
    return;
  }

  free(url->protocol);
  free(url->hostname);
  free(url->path);
  free(url);
}

int connect_to_server(const char *hostname, int port)
{
  struct addrinfo hints, *res, *p;
  int status;
  int sockfd = -1;
  char port_str[10];

  snprintf(port_str, sizeof(port_str), "%d", port);

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    return -1;
  }

  for (p = res; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) {
      perror("socket");
      continue;
    }

    printf("Socket created successfully with FD: %d\n", sockfd);

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("connect");
      close(sockfd);
      sockfd = -1;
      continue;
    }

    printf("Connected to server\n");
    break;
  }

  freeaddrinfo(res);
  return sockfd;
}

int get_and_print_response(int sockfd, const char *hostname, const char *path)
{
  char request[1024];
  int written = snprintf(request, sizeof(request),
                           "GET %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Connection: close\r\n"
                           "User-Agent: http-client/1.0\r\n"
                           "\r\n",
                           path, hostname);
  if (send(sockfd, request, written, 0) != written) {
    perror("send");
    return -1;
  }

  char buf[4096];
  long total_bytes = 0;

  for (;;) {
    int bytes_received = recv(sockfd, buf, sizeof(buf) - 1, 0);
    if (bytes_received <= 0) break;
    buf[bytes_received] = '\0';
    fwrite(buf, 1, bytes_received, stdout);
    total_bytes += bytes_received;
  }
  printf("\nReceived %ld bytes in total.\n", total_bytes);
  return 0;
}

int main(int argc, char *argv[])
{

  if (argc != 2) {
    printf("Usage: %s <http://example.com>\n", argv[0]);
    return 1;
  }

  ParsedUrl *parsed_url = parse_url(argv[1]);

  printf("Protocol: %s\n", parsed_url->protocol);
  printf("Hostname: %s\n", parsed_url->hostname);
  printf("Port: %d\n", parsed_url->port);
  printf("Path: %s\n", parsed_url->path);

  int sockfd = connect_to_server(parsed_url->hostname, parsed_url->port);

  if (sockfd == -1) {
    fprintf(stderr, "Failed to connect to server.\n");
    free_parsed_url(parsed_url);
  }
  get_and_print_response(sockfd, parsed_url->hostname, parsed_url->path);

  close(sockfd);
  free_parsed_url(parsed_url);

  return 0;
}
