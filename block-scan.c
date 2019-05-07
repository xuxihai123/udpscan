/**
 * gcc -o blockscan block-scan.c
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

const char *protoc[] = {"tcp", "udp"};
struct hostent *he;
struct ip *hdr;
struct icmp *icp;

// udp send packet
void tx_packet(int fd, int port) {
  char buf[1024];
  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  servaddr.sin_addr = *((struct in_addr *)he->h_addr);

  if (sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&servaddr,
             sizeof(servaddr)) < 0) {
    perror("*** sendto() failed ***");
  }
}

// udp recv packet
int rx_packet(int fd) {
  struct timeval poll;
  poll.tv_sec = 1;
  poll.tv_usec = 0;
  int iplen;
  char buf[1024];
  fd_set fds;
  while (1) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (select(fd + 1, &fds, NULL, NULL, &poll) > 0) {
      recvfrom(fd, &buf, sizeof(buf), 0x0, NULL, NULL);
    } else if (!FD_ISSET(fd, &fds))
      return 1;
    else
      perror("*** recvfrom() failed ***");

    hdr = (struct ip *)buf;
    iplen = hdr->ip_hl << 2;

    icp = (struct icmp *)(buf + iplen);

    if ((icp->icmp_type == ICMP_UNREACH) &&
        (icp->icmp_code == ICMP_UNREACH_PORT))
      return 0;
  }
}

void udpScan(int portlow, int porthigh) {
  int sendfd;
  int recvfd;
  struct servent *appl_name;
  // open send UDP socket
  if ((sendfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("*** socket(,,IPPROTO_UDP) failed ***n");
    exit(-1);
  }
  // open receive ICMP socket
  if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror("*** socket(,,IPPROTO_ICMP) failed ***n");
    exit(-1);
  }
  int scanPort;
  for (scanPort = portlow; scanPort <= porthigh; scanPort++) {
    tx_packet(sendfd, scanPort);

    if (rx_packet(recvfd) == 1) {
      appl_name = getservbyport(htons(scanPort), protoc[1]);

      if (appl_name != NULL)
        printf("port %d: %s\n", scanPort, appl_name->s_name);

      fflush(stdout);
    }
  }
  printf("scan finished.\n");
}

int main(int argc, char const *argv[]) {
  const char *host = argv[1];
  int startPort = atoi(argv[2]);
  int endPort = atoi(argv[3]);
  if (argc < 3) {
    printf("Usage: ./geoscan < hostname > < portlow > < porthigh >\n");
  }
  fprintf(stderr, "Scanning host=%s, protocol=udp, ports: %d -> %d\n", host,
          startPort, endPort);

  if ((he = gethostbyname(argv[1])) == NULL) {
    printf("*** gethostbyname() failed ***");
    exit(-1);
  }

  udpScan(startPort, endPort);  // udp scan
  return 0;
}
