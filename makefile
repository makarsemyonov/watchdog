MAKEFLAGS += --silent

CC = gcc
LIBS = -lpcap -pthread

watchdog: watchdog.c source/sniff.c source/parse.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

.PHONY: clean install

clean:
	rm -f watchdog

install:
	cp watchdog /usr/local/bin
	rm -f watchdog
