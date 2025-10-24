#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture.h"
#include "device_info.h"

void usage(const char *p) {
    fprintf(stderr, "Usage: %s [-o logfile] [-i interface] [-t seconds]\n", p);
}

int main(int argc, char **argv) {
    const char *outfile = "monitor.log";
    const char *ifname = NULL;
    int seconds = 0;
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outfile = argv[i+1]; i += 2;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ifname = argv[i+1]; i += 2;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            seconds = atoi(argv[i+1]); i += 2;
        } else {
            usage(argv[0]); return 1;
        }
    }

    FILE *f = fopen(outfile, "a");
    if (!f) { perror("fopen"); return 1; }
    collect_device_info(f);
    fclose(f);

    start_capture_all_interfaces(outfile, seconds, ifname);
    return 0;
}
