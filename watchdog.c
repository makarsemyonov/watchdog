#include "source/sniff.h"
#include "source/parse.h"

int main(int argc, char* argv[]) {
  char dev[PCAP_ERRBUF_SIZE];
  if (geteuid() != 0) {
    printf("This program can only run with superuser rights.\nUse \"sudo\"\n");
    return 0;
  }
  if (argc < 2){
    printf("Usage:\nsudo watchdog <flag>\n-s or --sniff\n-p or --parse\n");
    return 0;
  }
  if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--sniff") == 0){
    printf("\nCommands: \n/help - show help\n"
              "stop - stop the process\n"
              "pause - pause the process\n"
              "resume - resume the process\n"
              "stats - show current session statistics\n\n");

    printDevices();

    printf("\nEnter interface to sniff: \n-> ");
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
  }
  else if (strcmp(argv[1], "-p") == 0 || strcmp(argv[1], "--parse")){
    printf("Parsing sniff.log... Please wait\n");
    parse();
  }
  else {
    printf("Wrong mode! Try again\n");
  }
  return 0;
}