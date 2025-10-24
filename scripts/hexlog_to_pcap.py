#!/usr/bin/env python3
"""
hexlog_to_pcap.py

Parse the text log produced by packetmonitor, extract hex packet dumps, and write a pcap.

Usage:
  python3 scripts/hexlog_to_pcap.py monitor.log packets.pcap

This script is defensive: it accepts full-hex lines, lines with offsets ("0000: ..."), and lines containing hex with spaces.
"""
import argparse
import re
from pathlib import Path

try:
    from scapy.all import Ether, Raw, wrpcap
except Exception as e:
    print("Scapy is required. Install with: pip install scapy")
    raise

HEX_CHARS = re.compile(r"^[0-9A-Fa-f]+$")


def normalize_hex_line(line: str) -> str:
    """Strip common prefixes and whitespace to produce a pure hex string, or return empty if not hex."""
    s = line.strip()
    if not s:
        return ''
    # handle offset format like "0000: aa bb cc"
    if ':' in s:
        parts = s.split(':', 1)
        # if left part looks like an offset (1-4 hex digits), and right part has hex, use right
        left = parts[0].strip()
        right = parts[1].strip()
        if re.fullmatch(r"[0-9A-Fa-f]{1,4}", left):
            s = right
    # remove spaces and common separators
    s = re.sub(r"[\s:<>]", "", s)
    # if it starts with 0x, strip it
    if s.startswith('0x') or s.startswith('0X'):
        s = s[2:]
    # now s should be hex only
    if not s:
        return ''
    if HEX_CHARS.fullmatch(s) and (len(s) % 2 == 0):
        return s.lower()
    return ''


def extract_hex_lines(path: Path):
    hex_lines = []
    with path.open('r', errors='ignore') as fh:
        for raw in fh:
            s = normalize_hex_line(raw)
            if s:
                # heuristic: require at least 4 bytes (8 hex chars) to avoid false positives
                if len(s) >= 8:
                    hex_lines.append(s)
    return hex_lines


def hexlist_to_packets(hexlist):
    packets = []
    for i, hx in enumerate(hexlist, 1):
        raw = bytes.fromhex(hx)
        pkt = None
        try:
            pkt = Ether(raw)
        except Exception:
            # fallback to Raw wrapper so it still gets written to pcap
            pkt = Raw(load=raw)
        packets.append(pkt)
    return packets


def main():
    p = argparse.ArgumentParser(description='Convert packetmonitor text log hex dumps into a pcap using Scapy')
    p.add_argument('infile', nargs='?', default='monitor.log', help='text log file (default monitor.log)')
    p.add_argument('outfile', nargs='?', default='packets.pcap', help='output pcap file (default packets.pcap)')
    p.add_argument('--individual', action='store_true', help='write each packet to a separate pcap named packet_<n>.pcap')
    args = p.parse_args()

    inpath = Path(args.infile)
    if not inpath.exists():
        print(f"Input file not found: {inpath}")
        return 2

    hexlist = extract_hex_lines(inpath)
    if not hexlist:
        print("No hex packet lines found in the log.")
        return 1

    print(f"Found {len(hexlist)} packet hex entries; parsing with Scapy...")
    pkts = hexlist_to_packets(hexlist)

    outpath = Path(args.outfile)
    wrpcap(str(outpath), pkts)
    print(f"Wrote {len(pkts)} packets to {outpath}")

    if args.individual:
        for idx, pkt in enumerate(pkts, 1):
            pfn = Path(f"packet_{idx}.pcap")
            wrpcap(str(pfn), [pkt])
        print(f"Wrote individual packets to packet_<n>.pcap")

    # Print a short summary to stdout
    for idx, pkt in enumerate(pkts, 1):
        print(f"\n== Packet {idx}: {len(bytes(pkt))} bytes ==")
        try:
            print(pkt.summary())
            # show common layers
            if pkt.haslayer('IP'):
                ip = pkt.getlayer('IP')
                print(" IP:", ip.src, "->", ip.dst, "proto", ip.proto)
            if pkt.haslayer('TCP'):
                tcp = pkt.getlayer('TCP')
                print(" TCP:", tcp.sport, "->", tcp.dport, "flags", tcp.flags)
            if pkt.haslayer('UDP'):
                udp = pkt.getlayer('UDP')
                print(" UDP:", udp.sport, "->", udp.dport)
            if pkt.haslayer('ARP'):
                arp = pkt.getlayer('ARP')
                print(" ARP:", arp.psrc, "->", arp.pdst)
        except Exception as e:
            print("Failed to summarize packet:", e)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
