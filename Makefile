CC=gcc
CFLAGS=-O2 -Wall -I./src
LDFLAGS=-lpcap
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:.c=.o)

all: bin/packetmonitor

bin/packetmonitor: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

extract:
	python3 scripts/hexlog_to_pcap.py monitor.log packets.pcap || true

clean:
	rm -f bin/packetmonitor src/*.o
