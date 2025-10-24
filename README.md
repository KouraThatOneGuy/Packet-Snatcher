PacketMonitor - cross-platform packet capture + device info

This tool captures packets on the machine it runs on (only for devices you own) and logs basic packet headers and device information to a text log.

Security & legality
- Use only on devices/networks you own or have explicit permission to monitor.
- This tool is not stealthy, does not persist, and is intended for diagnostics and learning.

What it does
- Enumerates interfaces and captures packets (libpcap/Npcap).
- Logs timestamp, interface, basic L2/L3/L4 headers (Ethernet, IPv4/IPv6, TCP/UDP) and packet hex snippet to a text file.
- Collects device info: OS, hostname, network interfaces, MACs, IPs, CPU model (x86 CPUID via a small inline assembly snippet when available), uptime, memory.

Limitations and notes
- "All OS" support is best-effort. The code targets Linux/macOS (gcc/clang, libpcap) and Windows (MSVC + Npcap). Some platform-specific features use fallbacks.
- Reading some low-level registers on ARM may be restricted; the tool gathers CPU info from standard OS interfaces when assembly access isn't possible.
- Capturing requires elevated privileges: run with root/Administrator.

Build (Linux/macOS)

Requirements:
- libpcap development headers (libpcap-dev on Debian/Ubuntu, `brew install libpcap` on macOS)
- gcc/clang, make

Build:

```sh
cd /path/to/repo
make
```

Run:

```sh
sudo ./bin/packetmonitor -o monitor.log
```

By default it captures on all interfaces where supported. Use `-i <ifname>` to restrict to one interface.

Windows (overview)
- Install Npcap (https://nmap.org/npcap/).
- Build using Visual Studio: create a project and add the `src/*.c` files. Link against wpcap.lib and Packet.lib and Ws2_32.lib.
- Run as Administrator.

Usage
- `-o <logfile>` : text log file path (default: monitor.log)
- `-i <interface>` : capture one interface (optional)
- `-t <seconds>` : run for given seconds then exit (optional)

Files created
- `src/main.c` - arg parsing, orchestrates device info and capture
- `src/capture.c` - libpcap integration and packet callback
- `src/device_info.c` - device info collectors (includes small inline assembly CPUID for x86)
- `src/log.h` - simple logging helpers
- `Makefile` - build for Unix-like systems

If you want, I can now implement an eBPF-based monitor (Linux-only) for higher fidelity.```
