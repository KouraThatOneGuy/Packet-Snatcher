#pragma once

#include <stdio.h>
#include <time.h>
#include <stdarg.h>

static inline void write_log_header(FILE *f) {
    time_t t = time(NULL);
    fprintf(f, "=== PacketMonitor Log - %s\n", ctime(&t));
}

static inline void log_printf(FILE *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
}
