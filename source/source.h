#ifndef SOURCE_H
#define SOURCE_H

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static int exitFlag = 1;

void* commandThread(void* arg);
void printDevices();
void handlePacket(const char *packet, struct pcap_pkthdr header, FILE *file);
void sniff(const char* dev);

#endif