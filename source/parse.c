#include "parse.h"

void parse(){
    FILE *file = fopen("sniff.log", "r");;
    char line[MAX_LINE_LENGTH];
    if (file == NULL) {
        printf("Error opening file.\n");
        return;
    }
    int i = 0;
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        line[strcspn(line, "\n")] = '\0';
        i++;
        char *protocol = strtok(line, "[]");
        if (strcmp(protocol, "ARP") == 0){
            char *bytes = strtok(NULL, "[]");
            packetCounters[6]++;
            packetCounters[7]++;
            byteCounters[2] += atoi(bytes);
            byteCounters[3] += atoi(bytes);
        }
        else if (strcmp(protocol, "IPv4") == 0){
            char *transport_protocol = strtok(NULL, "[]");
            char *bytes = strtok(NULL, "[]");
            if (strcmp(transport_protocol, "tcp") == 0){
                packetCounters[6]++;
                packetCounters[0]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[0] += atoi(bytes);
            }
            else if (strcmp(transport_protocol, "udp") == 0){
                packetCounters[6]++;
                packetCounters[1]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[0] += atoi(bytes);
            }
            else if (strcmp(transport_protocol, "icmp") == 0){
                packetCounters[6]++;
                packetCounters[2]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[0] += atoi(bytes);
            }
        }
        else if (strcmp(protocol, "IPv6") == 0){
            char *transport_protocol = strtok(NULL, "[]");
            char *bytes = strtok(NULL, "[]");
            if (strcmp(transport_protocol, "tcp") == 0){
                packetCounters[6]++;
                packetCounters[3]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[1] += atoi(bytes);
            }
            else if (strcmp(transport_protocol, "udp") == 0){
                packetCounters[6]++;
                packetCounters[4]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[1] += atoi(bytes);
            }
            else if (strcmp(transport_protocol, "icmp") == 0){
                packetCounters[6]++;
                packetCounters[5]++;
                byteCounters[2] += atoi(bytes);
                byteCounters[1] += atoi(bytes);
            }
        }
    }
    printf("Parsed information:\n\n"
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