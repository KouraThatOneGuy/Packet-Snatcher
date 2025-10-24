#include "device_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#if defined(__linux__)
#include <sys/sysinfo.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#elif defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#endif

static void gather_uname(FILE *f) {
    struct utsname u;
    if (uname(&u) == 0) {
        fprintf(f, "OS: %s %s %s\n", u.sysname, u.release, u.machine);
    }
}

static void gather_uptime_mem(FILE *f) {
#ifdef __linux__
    struct sysinfo s;
    if (sysinfo(&s) == 0) {
        fprintf(f, "Uptime: %ld seconds\n", s.uptime);
        fprintf(f, "Total RAM: %llu MB\n", (unsigned long long)(s.totalram / 1024 / 1024));
    }
#else
    fprintf(f, "Uptime/Memory: platform-specific info not available in this build\n");
#endif
}

static void gather_interfaces(FILE *f) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        fprintf(f, "Could not get interfaces\n");
        return;
    }
    fprintf(f, "Interfaces:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        int family = ifa->ifa_addr->sa_family;
        char addr[INET6_ADDRSTRLEN] = "";
        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, addr, sizeof(addr));
        }
        fprintf(f, " - %s : %s\n", ifa->ifa_name, addr);
    }
    freeifaddrs(ifaddr);
}

#if defined(__x86_64__) || defined(_M_X64)
static void cpuid_vendor(char *out) {
    unsigned int eax, ebx, ecx, edx;
    eax = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "cpuid"
        : "=b" (ebx), "=c" (ecx), "=d" (edx), "=a" (eax)
        : "a" (0)
    );
    memcpy(out + 0, &ebx, 4);
    memcpy(out + 4, &edx, 4);
    memcpy(out + 8, &ecx, 4);
    out[12] = 0;
#else
    strcpy(out, "unknown");
#endif
}
#endif

void collect_device_info(FILE *f) {
    gather_uname(f);
    gather_uptime_mem(f);
    gather_interfaces(f);
#if defined(__x86_64__) || defined(_M_X64)
    char vendor[13];
    cpuid_vendor(vendor);
    fprintf(f, "CPU Vendor: %s\n", vendor);
#else
    fprintf(f, "CPU Vendor: platform not x86_64 or cpuid not available\n");
#endif
}
