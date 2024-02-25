#include "source/source.h"

int main() {
  char dev[PCAP_ERRBUF_SIZE];

  if (geteuid() != 0) {
    printf("This program can only run with superuser rights.\nUse \"sudo\"\n");
    return 0;
  }

  printDevices();

  printf("\nEnter interface to sniff: \n");
  fgets(dev, sizeof(dev), stdin);
  dev[strcspn(dev, "\n")] = '\0';

  printf("\nSniffing on %s...\nEnter \"stop\" to stop\n", dev);

  pthread_t thread;
  pthread_create(&thread, NULL, commandThread, NULL);

  sniff(dev);
  printf("\nLogs were saved to sniff.log. Finishing... \n");
  pthread_join(thread, NULL);
  return 0;
}