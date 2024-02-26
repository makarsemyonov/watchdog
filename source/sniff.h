#ifndef SNIFF_H
#define SNIFF_H

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
#include <time.h>

static int exitFlag = 1;
static int packetCounters[8];
static int byteCounters[4];

static pthread_mutex_t mutex;
static int flag = 1;

void* commandThread(void* arg);
void printDevices();
void handlePacket(const char *packet, struct pcap_pkthdr header, FILE *file);
void sniff(const char* dev);

#endif