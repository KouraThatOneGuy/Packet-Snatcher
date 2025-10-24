#include "capture.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "log.h"

static FILE *g_log = NULL;

static void print_hex(FILE *f, const u_char *buf, int len) {
    for (int i = 0; i < len; i++) {
        fprintf(f, "%02x", buf[i]);
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    FILE *f = (FILE *)user;
    struct tm *tm_info;
    char timebuf[64];
    time_t sec = h->ts.tv_sec;
    tm_info = localtime(&sec);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "\n--- Packet: %s.%06ld Len: %u\n", timebuf, (long)h->ts.tv_usec, h->len);
    // print first 128 bytes in hex
    int toprint = h->caplen < 128 ? h->caplen : 128;
    print_hex(f, bytes, toprint);
    fprintf(f, "\n");
    fflush(f);
}

int start_capture_all_interfaces(const char *outfile, int seconds, const char *ifname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return -1;
    }
    FILE *f = fopen(outfile, "a");
    if (!f) {
        perror("fopen");
        pcap_freealldevs(alldevs);
        return -1;
    }
    write_log_header(f);

    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (ifname && strcmp(d->name, ifname) != 0) continue;
        pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
        if (!handle) {
            fprintf(f, "Could not open %s: %s\n", d->name, errbuf);
            continue;
        }
        fprintf(f, "Starting capture on %s\n", d->name);
        // capture in a loop with timeout
        int ret = pcap_loop(handle, 0, packet_handler, (u_char *)f);
        (void)ret;
        pcap_close(handle);
    }

    pcap_freealldevs(alldevs);
    fclose(f);
    return 0;
}
