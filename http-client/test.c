#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    // Check if URL was provided
    if (argc < 2) {
        handle_error("Usage: ./http-client <URL>");
    }

    char *url = argv[1];
    char *protocol = NULL;
    char *hostname = NULL;
    int port = 0;
    char *path = NULL;

    // Find the protocol prefix
    char *protocol_end = strstr(url, "://");
    if (protocol_end == NULL) {
        handle_error("Invalid URL: Missing protocol prefix (://)");
    }

    // Extract protocol
    size_t protocol_len = protocol_end - url;
    protocol = malloc(protocol_len + 1);
    strncpy(protocol, url, protocol_len);
    protocol[protocol_len] = '\0';

    // Move pointer to the beginning of the hostname
    char *host_start = protocol_end + 3; // Skip "://"

    // Find the end of hostname (either ':', '/', or end of string)
    char *host_end = host_start;
    while (*host_end != '\0' && *host_end != ':' && *host_end != '/') {
        host_end++;
    }

    // Extract hostname
    size_t hostname_len = host_end - host_start;
    hostname = malloc(hostname_len + 1);
    strncpy(hostname, host_start, hostname_len);
    hostname[hostname_len] = '\0';

    // Determine port and path
    if (*host_end == ':') {
        // Custom port specified
        char *port_start = host_end + 1;
        char *port_end = port_start;
        while (*port_end != '\0' && *port_end != '/') {
            port_end++;
        }

        char port_str[16];
        size_t port_len = port_end - port_start;
        strncpy(port_str, port_start, port_len);
        port_str[port_len] = '\0';
        port = atoi(port_str);

        // Set path start after port
        if (*port_end == '/') {
            path = strdup(port_end);
        } else {
            path = strdup("/");
        }
    } else if (*host_end == '/') {
        // No custom port, path specified
        path = strdup(host_end);
        // Set default port based on protocol
        port = (strcmp(protocol, "https") == 0) ? 443 : 80;
    } else {
        // No custom port, no path specified
        path = strdup("/");
        port = (strcmp(protocol, "https") == 0) ? 443 : 80;
    }

    // Print extracted components for verification
    printf("Protocol: %s\n", protocol);
    printf("Hostname: %s\n", hostname);
    printf("Port: %d\n", port);
    printf("Path: %s\n", path);

    // Free allocated memory
    free(protocol);
    free(hostname);
    free(path);

    return 0;
}
