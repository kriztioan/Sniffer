/**
 *  @file   sniffer.c
 *  @brief  Sniffer
 *  @author KrizTioaN (christiaanboersma@hotmail.com)
 *  @date   2021-07-27
 *  @note   BSD-3 licensed
 *
 ***********************************************/

// Set some program issues
#define APP_NAME "Sniffer"
#define APP_MAJOR_VERSION 1
#define APP_MINOR_VERSION 0
#define APP_DESC "Sniffer program using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2021 KrizTioaN"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#define SIZE_ETHERNET 14

// Do some includes
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// Do some definitions
typedef struct _DATA {

  const u_char *payload;
  int fd;

} DATA;

#define ICMP 1
#define TCP 6
#define UDP 17

// Define some functions
void sigint(int sig);

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr,
                    const u_char *pckt);

void ethernet_handler(u_char *args, const u_char *ethernet);

void pup_handler(u_char *args, const u_char *pup);
void ip_handler(u_char *args, const u_char *ip);
void arp_handler(u_char *args, const u_char *arp);
void revarp_handler(u_char *args, const u_char *revarp);
void vlan_handler(u_char *args, const u_char *vlan);
void ipv6_handler(u_char *args, const u_char *ipv6);
void loopback_handler(u_char *args, const u_char *loopback);
void default_handler(u_char *args, const u_char *def);

void ether_arp_handler(u_char *args, const u_char *ether);
void default_arp_handler(u_char *args, const u_char *def);

void icmp_handler(u_char *args, const u_char *icmp);
void tcp_handler(u_char *args, const u_char *tcp);
void udp_handler(u_char *args, const u_char *udp);
void default_ip_handler(u_char *args, const u_char *def);

DATA *init_data_handler(DATA *data, const char *file);
int data_handler(DATA *data);
DATA *close_data_handler(DATA *data);

// Set some options
#define DUMPFILE "tcp.dmp"
#define SNAPLEN 65535
#define PROMISC 0
#define TOMS 1000
#define CNT 25

// loop stopped by signal SIGTERM
int sentinal = 1;

int main(int argc, char *argv[], char **envp) {

  // Display some general information
  printf("%s %d.%d - %s version %d.%d\n%s\n\n%s\n\n", APP_NAME,
         APP_MAJOR_VERSION, APP_MINOR_VERSION, APP_DESC, PCAP_VERSION_MAJOR,
         PCAP_VERSION_MINOR, APP_COPYRIGHT, APP_DISCLAIMER);

  // Check for filter
  if(argc < 2) {
    fprintf(stderr, "no filter specified\n");
    exit(1);
  }

  // Some definitions and initializations
  char *dev = NULL, errbuf[PCAP_ERRBUF_SIZE];

  // List all available devices
  pcap_if_t *alldevs = NULL, *currdev = NULL;

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    fprintf(stderr, "Unable to list devices: %s\n", errbuf);

  if (NULL != alldevs) {
    currdev = alldevs;

    pcap_addr_t *curraddr = NULL;

    printf("Available devices\n\n");
    while (NULL != currdev) {

      printf("Device name: %s", currdev->name);

      if (NULL != currdev->description)
        printf(", %s", currdev->description);

      if (PCAP_IF_LOOPBACK != currdev->flags)
        printf(" no");
      printf(" loopback interface ");

      curraddr = currdev->addresses;
      while (NULL != curraddr) {

        // inaddr.s_addr = curraddr->addr;
        // printf("associated address(es): %s", inet_ntoa(iaddr));
        curraddr = curraddr->next;
      }
      printf("\n");
      currdev = currdev->next;
    }
    printf("\n");
  }

  // Initialize the device that is going to be sniffed
  if (argc > 2)
    dev = argv[2];
  else
    dev = strdup(alldevs[0].name);

  pcap_freealldevs(alldevs);

  printf("Sniffing device: %s", dev);

  // Get IP and netmask of device
  bpf_u_int32 ip = 0, netmask = 0;

  if (pcap_lookupnet(dev, &ip, &netmask, errbuf) == -1)
    fprintf(stderr, "Unable to get netmask for device %s\n", errbuf);

  // Convert to human readable format and print
  char *humanip = NULL, *humannetmask = NULL;

  struct in_addr inaddr;

  inaddr.s_addr = ip;
  if ((humanip = inet_ntoa(inaddr)) == NULL)
    perror("inet_ntoa");
  printf(" on ip: %s", humanip);

  inaddr.s_addr = netmask;
  if ((humannetmask = inet_ntoa(inaddr)) == NULL)
    perror("inet_ntoa");
  printf(" and netmask: %s\n\n", humannetmask);

  // Opening the device for sniffing
  pcap_t *handle = pcap_open_live(dev, SNAPLEN, PROMISC, TOMS, errbuf);

  if (NULL == handle) {
    fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
    return (2);
  }

  if (argc < 2)
    free(dev);

  // Determine data link
  int *datalinks = NULL, n_links = 0;

  if ((n_links = pcap_list_datalinks(handle, &datalinks)) == -1)
    fprintf(stderr, "Unable to list datalinks: %s\n", pcap_geterr(handle));

  printf("Supported datalinks\n\n");
  for (int i = 0; i < n_links; i++)
    printf("Datalink: %s - %s\n", pcap_datalink_val_to_name(datalinks[i]),
           pcap_datalink_val_to_description(datalinks[i]));

  free(datalinks);
  datalinks = NULL;

  printf("\nData link selected: %s\n\n",
         pcap_datalink_val_to_name(pcap_datalink(handle)));

  // Filter traffic
  struct bpf_program filter;

  if (pcap_compile(handle, &filter, argv[1], 1, ip) == -1) {
    fprintf(stderr, "Unable to parse filter %s: %s\n", argv[1],
            pcap_geterr(handle));
    return (2);
  }

  if (pcap_setfilter(handle, &filter) == -1) {
    fprintf(stderr, "Unable to install filter %s: %s\n", argv[1],
            pcap_geterr(handle));
    return (2);
  }

  pcap_freecode(&filter);

  // Initialize data handling routine
  DATA *datahandler = init_data_handler(datahandler, DUMPFILE);

  // Start sniffing
  struct pcap_pkthdr header;

  const u_char *packet;

  signal(SIGINT, sigint);

  int catched = 0;
  while (sentinal) {

    if ((catched = pcap_dispatch(handle, CNT, packet_handler,
                                 (u_char *)datahandler)) == -1) {
      fprintf(stderr, "Dispatch failed: %s\n", pcap_geterr(handle));
      sentinal = 0;
    }
  }

  struct pcap_stat stats;

  if ((pcap_stats(handle, &stats)) == -1)
    fprintf(stderr, "Unable to get statistics : %s\n", pcap_geterr(handle));

  printf("\nFinished sniffing %d frames, %d dropped by Kernel.\n",
         stats.ps_recv, stats.ps_drop);

  datahandler = close_data_handler(datahandler);

  pcap_close(handle);

  return (0);
}

void sigint(int sig) { sentinal = 0; }

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr,
                    const u_char *pckt) {

  // Output packet header info
  printf("Packet length: %d bytes - timestamp: %s", hdr->len,
         ctime((const time_t *)&(hdr->ts.tv_sec)));

  ethernet_handler(args, pckt);

  // if(data_handler((DATA *) args) == -1)
  //  perror("write");
}

void ethernet_handler(u_char *args, const u_char *ethernet) {

  // Do the appropriate cast
  const struct ether_header *ethernetheader =
      (const struct ether_header *)ethernet;

  // Output the ethernet header info
  printf("MAC: %s ->",
         ether_ntoa((const struct ether_addr *)&(ethernetheader->ether_shost)));
  printf(" %s\n",
         ether_ntoa((const struct ether_addr *)&(ethernetheader->ether_dhost)));

  switch (ntohs(ethernetheader->ether_type)) {

  case ETHERTYPE_PUP:
    printf("PUP\n");
    pup_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_IP:
    printf("IP");
    ip_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_ARP:
    printf("ARP");
    arp_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_REVARP:
    printf("REARP\n");
    revarp_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_VLAN:
    printf("VLAN\n");
    vlan_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_IPV6:
    printf("IPV6\n");
    ipv6_handler(args, ethernet + sizeof(struct ether_header));
    break;

  case ETHERTYPE_LOOPBACK:
    printf("LOOPBACK\n");
    loopback_handler(args, ethernet + sizeof(struct ether_header));
    break;

  default:
    printf("Other: 0x%x\n", ntohs(ethernetheader->ether_type));
    default_handler(args, ethernet + sizeof(struct ether_header));
    break;
  };
}

void pup_handler(u_char *args, const u_char *pup) {

  printf("Yet to implement!\n");
};

void ip_handler(u_char *args, const u_char *ip) {

  // Do the appropriate cast
  const struct ip *ipheader = (const struct ip *)ip;

  // Output IP header info
  printf(" version %d", ipheader->ip_v);

  if (ipheader->ip_v < 4) {
    fprintf(stderr, "Can't handle IP version %d\n", ipheader->ip_v);
    return;
  }

  u_int off = ntohs(ipheader->ip_off);
  if ((off & 0x1fff) == 0) {

    register struct hostent *host;

    char *src = inet_ntoa(ipheader->ip_src), *dst = NULL;
    printf(" %s", src);

    if ((host = gethostbyaddr(&(ipheader->ip_src), (socklen_t)strlen(src),
                              AF_INET)) != NULL)
      printf(" (%s)", host->h_name);

    dst = inet_ntoa(ipheader->ip_dst);
    printf(" -> %s", dst);

    if ((host = gethostbyaddr(&(ipheader->ip_dst), (socklen_t)strlen(dst),
                              AF_INET)) != NULL)
      printf(" (%s)\n", host->h_name);
    else
      printf("\n");
  }

  switch (ipheader->ip_p) {

  case ICMP:
    printf("ICMP");
    icmp_handler(args, ip + ipheader->ip_hl * 4);
    break;

  case TCP:
    printf("TCP");
    tcp_handler(args, ip + ipheader->ip_hl * 4);
    break;

  case UDP:
    printf("UDP");
    udp_handler(args, ip + ipheader->ip_hl * 4);
    break;

  default:
    printf("Other: 0x%x", ipheader->ip_p);
    default_handler(args, ip + ipheader->ip_hl * 4);
    break;
  };
}

void arp_handler(u_char *args, const u_char *arp) {

  // Do the appropriate cast
  const struct arphdr *arpheader = (const struct arphdr *)arp;

  // Output arp header info
  switch (arpheader->ar_hrd) {

  case ARPHRD_ETHER:
    ether_arp_handler(args, arp);
    break;

  default:
    default_arp_handler(args, arp);
    break;
  }
}

void revarp_handler(u_char *args, const u_char *revarp) {
  printf("Yet to implement!\n");
}
void vlan_handler(u_char *args, const u_char *vlan) {
  printf("Yet to implement!\n");
}
void ipv6_handler(u_char *args, const u_char *ipv6) {
  printf("Yet to implement!\n");
}
void loopback_handler(u_char *args, const u_char *loopback) {
  printf("Yet to implement!\n");
}
void default_handler(u_char *args, const u_char *def) {
  printf("Yet to implement!\n");
}

void ether_arp_handler(u_char *args, const u_char *ether) {

  // Do the appropriate cast
  const struct arphdr *arpheader = (const struct arphdr *)ether;

  // Output arp info
  const u_char *ar_sha = (((const u_char *)((arpheader) + 1)) + 0),
               *ar_spa =
                   (((const u_char *)((arpheader) + 1)) + (arpheader)->ar_hln),
               *ar_tha = (((const u_char *)((arpheader) + 1)) +
                          (arpheader)->ar_hln + (arpheader)->ar_pln),
               *ar_tpa = (((const u_char *)((arpheader) + 1)) +
                          2 * (arpheader)->ar_hln + (arpheader)->ar_pln);

  in_addr_t addr;

  char *dst = (char *)malloc(arpheader->ar_pln * sizeof(char));

  register struct hostent *host;

  switch (arpheader->ar_op) {
  case ARPOP_REQUEST:
  case ARPOP_REVREQUEST:
  case ARPOP_INVREQUEST:

    printf(" who has %s",
           inet_ntop(AF_INET, ar_tpa, dst, 4 * arpheader->ar_pln));

    memcpy(&addr, ar_tpa, sizeof(in_addr_t));
    if ((host = gethostbyaddr((char *)&addr, (socklen_t)sizeof(in_addr_t),
                              AF_INET)) != NULL)
      printf(" (%s)", host->h_name);

    printf(" tell %s", inet_ntop(AF_INET, ar_spa, dst, 4 * arpheader->ar_pln));

    memcpy(&addr, ar_spa, sizeof(in_addr_t));
    if ((host = gethostbyaddr((char *)&addr, (socklen_t)sizeof(in_addr_t),
                              AF_INET)) != NULL)
      printf(" (%s)\n\n", host->h_name);
    else
      printf("\n\n");

    break;

  case ARPOP_REPLY:
  case ARPOP_REVREPLY:
  case ARPOP_INVREPLY:

    memcpy(&addr, ar_spa, sizeof(in_addr_t));
    printf(" %s", inet_ntop(AF_INET, ar_spa, dst, 4 * arpheader->ar_pln));

    if ((host = gethostbyaddr((char *)&addr, (socklen_t)sizeof(in_addr_t),
                              AF_INET)) != NULL)
      printf(" (%s)", host->h_name);

    memcpy(&addr, ar_tpa, sizeof(in_addr_t));
    printf(" has %s", inet_ntop(AF_INET, ar_tpa, dst, 4 * arpheader->ar_pln));

    if ((host = gethostbyaddr((char *)&addr, (socklen_t)sizeof(in_addr_t),
                              AF_INET)) != NULL)
      printf(" (%s)\n\n", host->h_name);
    else
      printf("\n\n");

    break;
  };

  free(dst);
  dst = NULL;
}

void default_arp_handler(u_char *args, const u_char *def) {
  printf("Yet to implement!\n");
}

void icmp_handler(u_char *args, const u_char *icmp) {

  // Do the appropriate cast
  const struct icmp *icmpheader = (const struct icmp *)icmp;

  // Output icmp header info
  printf(" type 0X%x subtype 0X%x\n\n", icmpheader->icmp_type,
         icmpheader->icmp_code);
}

void tcp_handler(u_char *args, const u_char *tcp) {

  // Do the appropriate casts
  DATA *data = (DATA *)args;

  const struct tcphdr *tcpheader = (const struct tcphdr *)tcp;

  // Output tcp header info
  printf(" port %d -> %d\n\n", tcpheader->th_sport, tcpheader->th_dport);

  // Content
  data->payload = tcp + tcpheader->th_off * 4;

  printf("%s\n\n", data->payload);
}

void udp_handler(u_char *args, const u_char *udp) {

  // Do the appropriate cast
  const struct udphdr *udpheader = (const struct udphdr *)udp;

  // Output udp header info
  printf(" port %d -> %d\n\n", udpheader->uh_sport, udpheader->uh_dport);

  // Content
  const u_char *payload = udp + sizeof(struct udphdr);

  printf("%s\n\n", payload);
}

void default_ip_handler(u_char *args, const u_char *def) {
  printf("Yet to implement!\n");
}

DATA *init_data_handler(DATA *data, const char *file) {

  data = (DATA *)malloc(sizeof(DATA));

  data->payload = NULL;

  // open file
  if ((data->fd = open(file, O_WRONLY | O_CREAT, 644)) == -1) {
    free(data);
    perror("open");
    return (NULL);
  }

  return (data);
}

int data_handler(DATA *data) {

  if (data != NULL)
    return (0);

  return (
      write(data->fd, (char *)data->payload, strlen((char *)data->payload)));
}

DATA *close_data_handler(DATA *data) {

  if (data == NULL)
    return (NULL);

  close(data->fd);

  free(data);

  data = NULL;

  return (data);
}
