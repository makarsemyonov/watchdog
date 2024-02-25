#include "source/source.h"

int main() {
  char dev[PCAP_ERRBUF_SIZE];

  if (geteuid() != 0) {
    printf("This program can only run with superuser rights.\nUse \"sudo\"\n");
    return 0;
  }

  printf("Commands: \n/help - show help\n"
             "/stop - stop the process\n"
             "/pause - pause the process\n"
             "/resume - resume the process\n"
             "/stats - show current session statistics\n\n");

  printDevices();

  printf("\nEnter interface to sniff: \n[+] ");
  fgets(dev, sizeof(dev), stdin);
  dev[strcspn(dev, "\n")] = '\0';

  printf("\nSniffing on %s...\n\n", dev);

  pthread_t thread;
  pthread_create(&thread, NULL, commandThread, NULL);
  pthread_mutex_init(&mutex, NULL);
  sniff(dev);
  printf("\nLogs were saved to sniff.log. Finishing... \n");
  pthread_join(thread, NULL);
  pthread_mutex_destroy(&mutex);
  return 0;
}
