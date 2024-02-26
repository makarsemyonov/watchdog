#ifndef PARSE_H
#define PARSE_H

#define MAX_LINE_LENGTH 128

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

static int packetCounters[8];
static int byteCounters[4];

void parse();

#endif