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

SSL_CTX *ctx = NULL;

void handle_error(const char *msg)
{
  perror(msg);
  exit(EXIT_FAILURE);
}

void init_openssl()
{
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) {
      fprintf(stderr, "SSL_CTX_new failed\n");
      ERR_print_errors_fp(stderr);
      exit(1);
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

  if (!SSL_CTX_set_default_verify_paths(ctx)) {
      fprintf(stderr, "Failed to set default verify paths\n");
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ctx);
      exit(1);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void cleanup_openssl()
{
  if (ctx != NULL) {
    SSL_CTX_free(ctx);
    ctx = NULL;
  }
  EVP_cleanup();
}

int main(int argc, char *argv[])
{
  init_openssl();

  if (argc != 2) {
    printf("Usage: %s <http://example.com>\n", argv[0]);
    cleanup_openssl();
    return 1;
  }

  char *url = argv[1];
  char *protocol = NULL;
  char *hostname = NULL;
  int port = 0; // 80 for http, 443 for https
  char *path = NULL;

  // Parse the URL
  char *protocol_end = strstr(url, "://");
  if (protocol_end == NULL) {
    fprintf(stderr, "Invalid URL: Missing protocol prefix (://). Assuming http://\n");
    // Default to HTTP if no protocol
    protocol = strdup("http");
    hostname = strdup(url);
    port = 80;
    path = strdup("/");
  } else {
    size_t protocol_len = protocol_end - url;
    protocol = malloc(protocol_len + 1);
    strncpy(protocol, url, protocol_len);
    protocol[protocol_len] = '\0';

    char *host_start = protocol_end + 3;
    char *host_end = host_start;
    while (*host_end != '\0' && *host_end != '/' && *host_end != ':') {
      host_end++;
    }

    size_t hostname_len = host_end - host_start;
    hostname = malloc(hostname_len + 1);
    strncpy(hostname, host_start, hostname_len);
    hostname[hostname_len] = '\0';

    if (*host_end == ':') {
      char *port_start = host_end + 1; // Skip the colon
      char *port_end = port_start;
      while (*port_end != '\0' && *port_end != '/') {
        port_end++;
      }
      size_t port_len = port_end - port_start;
      char port_str[16];
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
  }

  printf("Protocol: %s\n", protocol);
  printf("Hostname: %s\n", hostname);
  printf("Port: %d\n", port);
  printf("Path: %s\n", path);

  // Convert port to string for getaddrinfo
  char port_str[10];
  snprintf(port_str, sizeof(port_str), "%d", port);

  // Resolve hostname to an IP address
  struct addrinfo hints, *res, *p;
  int status;
  int sockfd = -1;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    free(protocol);
    free(hostname);
    free(path);
    cleanup_openssl();
    exit(1);
  }

  // Create socket and connect
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

  if (sockfd == -1) {
    fprintf(stderr, "Failed to create and connect socket\n");
    freeaddrinfo(res);
    free(protocol);
    free(hostname);
    free(path);
    cleanup_openssl();
    exit(1);
  }

  freeaddrinfo(res); // Free addrinfo after use

  // SSL handshake only for HTTPS
  SSL *ssl = NULL;
  if (strcmp(protocol, "https") == 0) {
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
      fprintf(stderr, "SSL_new failed\n");
      ERR_print_errors_fp(stderr);
      close(sockfd);
      free(protocol);
      free(hostname);
      free(path);
      cleanup_openssl();
      exit(1);
    }

    if (SSL_set_fd(ssl, sockfd) != 1) {
      fprintf(stderr, "SSL_set_fd failed\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(sockfd);
      free(protocol);
      free(hostname);
      free(path);
      cleanup_openssl();
      exit(1);
    }

    if (SSL_connect(ssl) != 1) {
      fprintf(stderr, "SSL_connect failed\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(sockfd);
      free(protocol);
      free(hostname);
      free(path);
      cleanup_openssl();
      exit(1);
    }

    printf("SSL handshake successful. Connection is secure.\n");
  } else {
    printf("Using plain HTTP connection\n");
  }

  // Send HTTP GET request
  char request[1024];
  snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
  printf("Sending request:\n%s\n", request);

  int bytes_sent;
  if (ssl) {
    bytes_sent = SSL_write(ssl, request, strlen(request));
  } else {
    bytes_sent = send(sockfd, request, strlen(request), 0);
  }

  if (bytes_sent < 0) {
    perror("send");
    if (ssl) SSL_free(ssl);
    close(sockfd);
    free(protocol);
    free(hostname);
    free(path);
    cleanup_openssl();
    exit(1);
  }

  // Read and print the response
  char response[4096];
  int bytes_received;
  printf("Response:\n");

  while (1) {
    if (ssl) {
      bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
    } else {
      bytes_received = recv(sockfd, response, sizeof(response) - 1, 0);
    }

    if (bytes_received < 0) {
      perror("recv");
      break;
    } else if (bytes_received == 0) {
      break; // Connection closed
    }

    response[bytes_received] = '\0';
    printf("%s", response);
  }

  printf("\n");

  // Cleanup
  if (ssl) {
    SSL_free(ssl);
  }
  close(sockfd);
  free(protocol);
  free(hostname);
  free(path);
  cleanup_openssl();

  return 0;
}
