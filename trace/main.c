#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64
#define TIMEOUT_SEC 1

struct icmp_packet {
  struct icmphdr header;
  char data[PACKET_SIZE - sizeof(struct icmphdr)];
};

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short *w;

    for (w = buf; len > 1; len -= 2) {
        sum += *w++;
    }
    if (len == 1) {
        sum += *(unsigned char *)w;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "Error: This program must be run with root privileges.\n");
        return 1;
    }

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <destination_hostname_or_ip>\n", argv[0]);
        return 1;
    }

    char *target_host = argv[1];
    struct hostent *host_info;
    struct sockaddr_in dest_addr, recv_addr;
    int sock;
    int ttl = 1;
    int received_reply = 0;

    host_info = gethostbyname(target_host);
    if (host_info == NULL) {
        herror("gethostbyname");
        return 1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    memcpy(&dest_addr.sin_addr, host_info->h_addr, host_info->h_length);

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
    }

    printf("Tracing route to %s (%s) with a maximum of %d hops.\n", target_host, inet_ntoa(dest_addr.sin_addr), MAX_HOPS);
    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt");
            close(sock);
            return 1;
        }

        struct timeval tv;
        tv.tv_sec = TIMEOUT_SEC;
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt timeout");
            close(sock);
            return 1;
        }

        struct icmp_packet packet;
        memset(&packet, 0, sizeof(packet));
        packet.header.type = ICMP_ECHO;
        packet.header.code = 0;
        packet.header.un.echo.id = getpid();
        packet.header.un.echo.sequence = ttl;
        packet.header.checksum = checksum(&packet, sizeof(packet));

        printf("%2d  ", ttl);

        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            close(sock);
            return 1;
        }

        char recv_buffer[PACKET_SIZE];
        socklen_t addr_len = sizeof(recv_addr);
        int bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

        if (bytes_received < 0) {
            printf("*\n");
        } else {
            struct iphdr *ip_header = (struct iphdr *)recv_buffer;
            struct icmphdr *icmp_header = (struct icmphdr *)(recv_buffer + (ip_header->ihl * 4));

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(recv_addr.sin_addr), ip_str, INET_ADDRSTRLEN);

            if (icmp_header->type == ICMP_TIME_EXCEEDED) {
                printf("%s\n", ip_str);
            }
            else if (icmp_header->type == ICMP_ECHOREPLY) {
                printf("%s\n", ip_str);
                received_reply = 1;
                break;
            } else {
                printf("Error: Unexpected ICMP type %d from %s\n", icmp_header->type, ip_str);
            }
        }
    }

    if (!received_reply) {
        printf("Trace complete. Destination may be unreachable.\n");
    }

    close(sock);
    return 0;
}
