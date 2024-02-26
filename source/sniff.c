#include "sniff.h"

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
      printf("[*] %s\n", d->name);
      struct pcap_addr *a;
      for (a = d->addresses; a != NULL; a = a->next) {
          if (a->addr->sa_family == AF_INET) {
              printf("    IP Address: %s\n", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
              printf("    Subnet Mask: %s\n", inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
          }
      }
    }
  }
  pcap_freealldevs(alldevs);
}

void handlePacket(const char *packet, struct pcap_pkthdr header, FILE *file) {
  struct ether_header *eth_header;
  struct ip *ip_header;
  struct ip6_hdr *ip6_header;
  struct iphdr *ip_head = (struct iphdr *)(packet + sizeof(struct ether_header));
  eth_header = (struct ether_header *)packet;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    char* proto;
    if (ip_head->protocol == IPPROTO_TCP) {
      proto = "tcp";
      packetCounters[0]++;
      packetCounters[6]++;
    }
    else if (ip_head->protocol == IPPROTO_UDP){
      proto = "udp";
      packetCounters[1]++;
      packetCounters[6]++;
    }
    else if (ip_head->protocol == IPPROTO_ICMP) {
      proto = "icmp";
      packetCounters[2]++;
      packetCounters[6]++;
    }
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));
    fprintf(file, "[IPv4][%s][%d] Source IP: %s, Destination IP: %s\n", proto,
            header.len, src_ip, dst_ip);
    byteCounters[0] += header.len;
    byteCounters[2] += header.len;
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    char *proto;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    if (ip6_header->ip6_nxt == IPPROTO_TCP) {
      proto = "tcp";
      packetCounters[3]++;
      packetCounters[6]++;
    }
    else if (ip6_header->ip6_nxt == IPPROTO_UDP){
      proto = "udp";
      packetCounters[4]++;
      packetCounters[6]++;
    }
    else if (ip_head->protocol == IPPROTO_ICMP) {
      proto = "icmp";
      packetCounters[5]++;
      packetCounters[6]++;
    }
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    fprintf(file, "[IPv6][%s][%d] Source IP: %s, Destination IP: %s\n", proto, header.len,
            src_ip, dst_ip);
    byteCounters[1] += header.len;
    byteCounters[2] += header.len;
  }
  else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
    packetCounters[7]++;
    byteCounters[3]++;
    fprintf(file, "[ARP] %d bytes\n", header.len);
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
    pthread_mutex_lock(&mutex);
    if (flag == 0) {
      pthread_mutex_unlock(&mutex);
      continue;
    }
    pthread_mutex_unlock(&mutex);
    packet = pcap_next(handle, &header);
    handlePacket(packet, header, file);
  }

  pcap_close(handle);
}

void *commandThread(void *arg) {
  char command[100];
  while (1) {
    printf("-> ");
    fgets(command, sizeof(command), stdin);
    if (strcmp(command, "stop\n") == 0) {
      printf("Stopping the process...\n");
      exitFlag = 0;
      break;
    }
    else if (strcmp(command, "/help\n") == 0) {
      printf("help - show help\n"
             "stop - stop the process\n"
             "pause - pause the process\n"
             "resume - resume the process\n"
             "stats - show current statistics\n");
    }
    else if (strcmp(command, "pause\n") == 0) {
      pthread_mutex_lock(&mutex);
      flag = 0;
      pthread_mutex_unlock(&mutex);
      printf("Sniffing paused...\n");
    }
    else if (strcmp(command, "resume\n") == 0) {
      pthread_mutex_lock(&mutex);
      flag = 1;
      pthread_mutex_unlock(&mutex);
      printf("Sniffing resumed\n");
    }
    else if (strcmp(command, "stats\n") == 0) {
      printf("This session statistics\n"
             "If you need all sniff statistics, use \"--parse/-f\" flag beyond active session\n"
             "      |\ttcp\t|\tudp\t|\ticmp\t|\tbytes\n"
             "--------------------------------------------------------------------\n"
             "IPv4  |\t%d\t|\t%d\t|\t%d\t|\t%d\t\n"
             "IPv6  |\t%d\t|\t%d\t|\t%d\t|\t%d\t\n"
             "ARP   |\t\t\t%d\t\t\t|\t%d\n\n"
             "--------------------------------------------------------------------\n"
             "All   |\t\t\t%d\t\t\t|\t%d\n\n", packetCounters[0], packetCounters[1],
             packetCounters[2], byteCounters[0], packetCounters[3], packetCounters[4],
             packetCounters[5], byteCounters[1], packetCounters[7], byteCounters[3], packetCounters[6], byteCounters[2]);
    }
    else {
      printf("Wrong command!\n");
    }
  }
  return NULL;
}
