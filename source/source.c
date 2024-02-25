#include "source.h"

void printDevices() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    printf("Unknown error: %s\n", errbuf);
    return;
  }

  if (alldevs == NULL) {
    printf(
        "No interfaces found! Make sure you have the necessary permissions.\n");
    return;
  }
  printf("Available interfaces:\n\n");
  for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
    if (d->flags & PCAP_IF_UP && d->flags & PCAP_IF_RUNNING) {
      printf("-> %s\n", d->name);
    }
  }
  pcap_freealldevs(alldevs);
}

void handlePacket(const char *packet, struct pcap_pkthdr header, FILE *file) {
  struct ether_header *eth_header;
  struct ip *ip_header;
  struct ip6_hdr *ip6_header;
  eth_header = (struct ether_header *)packet;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));
    fprintf(file, "[IPv4] Source IP: %s, Destination IP: %s, %d bytes\n",
            src_ip, dst_ip, header.len);
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    fprintf(file, "[IPv6] Source IP: %s, Destination IP: %s, %d bytes\n",
            src_ip, dst_ip, header.len);
  }
}

void sniff(const char *dev) {
  const char *packet;
  struct pcap_pkthdr header;
  char errbuf[PCAP_ERRBUF_SIZE];

  FILE *file = fopen("sniff.log", "a");
  if (file == NULL) {
    printf("Error opening file\n");
    return;
  }

  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    printf("Error opening device: %s\n", errbuf);
    return;
  }
  while (exitFlag) {
    packet = pcap_next(handle, &header);
    handlePacket(packet, header, file);
  }

  pcap_close(handle);
}

void *commandThread(void *arg) {
  char command[100];
  while (1) {
    fgets(command, sizeof(command), stdin);
    if (strcmp(command, "stop\n") == 0) {
      exitFlag = 0;
      break;
    }
  }
  return NULL;
}
