/*
 * Simple Ping Program
 *
 * A basic implementation of the 'ping' utility using raw sockets.
 * This program sends ICMP ECHO_REQUEST packets and listens for
 * ICMP ECHO_REPLY packets to measure round-trip time.
 *
 * Note: This program requires root privileges to create raw sockets.
 * You must run it with 'sudo'.
 *
 * Linux implementation of ping: https://github.com/torvalds/linux/blob/master/net/ipv4/ping.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>

#include "ping_utils.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname or IP>\n", argv[0]);
        exit(1);
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Error creating socket. Must be run with root privileges.");
        exit(1);
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_aton(argv[1], &dest_addr.sin_addr) == 0) {
        struct hostent *host_info = gethostbyname(argv[1]);
        if (host_info == NULL) {
            fprintf(stderr, "Invalid hostname or IP address: %s\n", argv[1]);
            exit(1);
        }
        dest_addr.sin_addr = *(struct in_addr *)host_info->h_addr;
    }

    int sequence_num = 0;
    while (1) {
        char send_buffer[64];
        memset(send_buffer, 0, sizeof(send_buffer));

        struct icmphdr *icmp_hdr = (struct icmphdr *)send_buffer;
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = getpid(); // Use process ID as unique identifier
        icmp_hdr->un.echo.sequence = sequence_num++;

        memset(send_buffer + sizeof(struct icmphdr), 'E', 64 - sizeof(struct icmphdr));

        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = checksum(send_buffer, sizeof(send_buffer));

        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        ssize_t bytes_sent = sendto(sock, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0) {
            perror("sendto");
            close(sock);
            exit(1);
        }

        char recv_buffer[1500];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        ssize_t bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from_addr, &from_len);
        if (bytes_received < 0) {
            perror("recvfrom");
            close(sock);
            exit(1);
        }

        struct timeval end_time;
        gettimeofday(&end_time, NULL);


        struct iphdr* ip_hdr = (struct iphdr *) recv_buffer;

        int ip_hdr_len = ip_hdr-> ihl * 4;
        struct icmphdr* recv_icmp_hdr = (struct icmphdr *) (recv_buffer + ip_hdr_len);

        if (recv_icmp_hdr->type == ICMP_ECHOREPLY) {
            if (recv_icmp_hdr->un.echo.id == getpid()) {
                if (recv_icmp_hdr->un.echo.sequence == sequence_num - 1) {
                    long long diff_us = (end_time.tv_sec - start_time.tv_sec) * 100000 + (end_time.tv_usec - start_time.tv_usec);
                    double rtt_ms = (double) diff_us / 1000.0;

        printf("Received %ld bytes from %s: icmp_seq=%d time=%.2f ms\n",
               bytes_received, inet_ntoa(from_addr.sin_addr), icmp_hdr->un.echo.sequence, rtt_ms); // Placeholder for RTT
                }
            }
        }

        sleep(1);
    }

    close(sock);

    return 0;
}
