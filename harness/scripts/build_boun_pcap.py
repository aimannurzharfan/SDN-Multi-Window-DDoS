#!/usr/bin/env python3
"""
build_boun_pcap.py — one-shot converter: BOUN TCP CSV -> replayable PCAP.

The Boğaziçi (BOUN) DDoS dataset ships as an anonymised, packet-level CSV
(one captured frame per row, TCP flags encoded as the strings "Set"/"Not set").
For a live Mininet replay we need an actual PCAP whose packet timestamps carry
the original inter-arrival timing, so tcpreplay can reproduce the native pace.

This script streams the CSV row-by-row (never loading it all into memory) and,
for every row, emits one Ethernet/IPv4/TCP frame whose pcap timestamp equals the
CSV relative Time. The anonymised source IPs are kept verbatim — they ARE the
spoofed attack sources and must be preserved for the entropy / revisit signals.

Frame construction
------------------
scapy's high-level Ether()/IP()/TCP() build is ~9.5k pkt/s — ~16 min for 9.3M
rows. We instead hand-pack the 54-byte header with struct and write via scapy's
RawPcapWriter (~270k pkt/s, <1 min). The frames still dissect cleanly with
scapy/Ryu (verified: correct src/dst/ports/flags, valid IPv4 checksum), which is
all the detector's packet_in parser reads. TCP checksum is left zero (tcpreplay
sends as-is; Ryu does not verify it).

Flag mapping (per row): SYN=0x02 if SYN=="Set", ACK=0x10 if ACK=="Set",
RST=0x04 if RST=="Set". This preserves the three handshake classes the detector
and eval_boun.py key on:
    pureSYN  = SYN set,  ACK not set
    SYN-ACK  = SYN set,  ACK set
    bareACK  = SYN not set, ACK set

Output: datasets/boun/boun_tcp.pcap
Usage:  python3 harness/scripts/build_boun_pcap.py
"""

import csv
import os
import socket
import struct
import sys
import time

from scapy.all import RawPcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CSV_PATH = os.path.join(REPO, "datasets", "boun", "BOUN_DDoS dataset", "BOUN_TCP_Anon.csv")
PCAP_PATH = os.path.join(REPO, "datasets", "boun", "boun_tcp.pcap")

# Expected verification targets (from the probe / Erhan & Anarim).
# EXPECT_TOTAL_ROWS is the raw CSV line count across ALL link/transport
# protocols. Only the TCP rows become frames in this pcap (see note below), so
# the written-frame target is EXPECT_TCP_ROWS.
EXPECT_TOTAL_ROWS = 9335605
EXPECT_TCP_ROWS = 6090873
# Handshake targets over the TCP-only universe (== eval_boun.py's evaluation
# set, verified). The probe's all-protocol tally is slightly higher — pureSYN
# 181,840 / SYN-ACK 39,370 / bareACK 5,858,586 — because it counts SYN/ACK bits
# on ~220 non-TCP frames (e.g. the 252 "ICMP,TCP" rows) that eval_boun excludes.
EXPECT_PURE_SYN = 181719
EXPECT_SYN_ACK = 39369
EXPECT_BARE_ACK = 5858488
PROBE_PURE_SYN, PROBE_SYN_ACK, PROBE_BARE_ACK = 181840, 39370, 5858586
EXPECT_DURATION = 482.7

# We build frames ONLY for rows whose TCP_Protocol column == "TCP", exactly the
# universe eval_boun.py evaluates (its parse_csv skips every non-"TCP" row). The
# other 3,244,732 rows are UDP (2.42M), GRE (0.77M), ICMP/IGMP/IPv6/empty, whose
# "IP" columns actually hold MAC addresses or v6 literals and carry no SYN/ACK
# signal. Encoding them as synthetic TCP would inflate the entropy / revisit /
# packet-volume signals and break direct comparability with the offline
# evaluator. The three handshake counts below are defined over this same TCP
# universe, so keeping TCP-only reproduces them exactly.
KEEP_PROTO = "TCP"

SYN = 0x02
ACK = 0x10
RST = 0x04

# Fixed L2 header: broadcast dst so the OVS table-miss floods it; src = h16 MAC
# (00:00:00:00:00:10 under Mininet autoSetMacs). Neither affects detection,
# which keys on the IPv4 source.
ETH = struct.pack("!6s6sH",
                  b"\xff\xff\xff\xff\xff\xff",
                  b"\x00\x00\x00\x00\x00\x10",
                  0x0800)

# Pre-built struct packers (module-level for speed).
_ip_pack = struct.Struct("!BBHHHBBH4s4s").pack
_tcp_pack = struct.Struct("!HHIIBBHHH").pack


def ip_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_frame(srcb: bytes, dstb: bytes, sport: int, dport: int,
                flags: int, ttl: int) -> bytes:
    # IPv4: ihl=5 ver=4, total len 40 (20 IP + 20 TCP), proto=6 (TCP).
    iph = _ip_pack(0x45, 0, 40, 0, 0, ttl, 6, 0, srcb, dstb)
    iph = _ip_pack(0x45, 0, 40, 0, 0, ttl, 6, ip_checksum(iph), srcb, dstb)
    # TCP: data offset 5 (0x50), window 8192, checksum 0.
    tcph = _tcp_pack(sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)
    return ETH + iph + tcph


def to_int(s: str, default: int) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


def main() -> int:
    if not os.path.exists(CSV_PATH):
        print(f"ERROR: CSV not found: {CSV_PATH}")
        return 1

    print(f"[build] source CSV : {CSV_PATH}")
    print(f"[build] output PCAP: {PCAP_PATH}")
    print("[build] streaming rows -> frames (RawPcapWriter) ...", flush=True)

    writer = RawPcapWriter(PCAP_PATH, linktype=1, sync=False)
    writer._write_header(b"")

    rows = 0
    written = 0
    bad_ip = 0
    pure_syn = syn_ack = bare_ack = 0
    max_t = 0.0
    min_t = None
    t_wall = time.time()

    with open(CSV_PATH, newline="") as f:
        r = csv.reader(f)
        header = next(r)
        ix = {name: i for i, name in enumerate(header)}
        ti = ix["Time"]
        si, di = ix["Source_ip"], ix["Destination_IP"]
        spi, dpi = ix["Source_Port"], ix["Destination_Port"]
        syni, acki, rsti = ix["SYN"], ix["ACK"], ix["RST"]
        ttli = ix["TTL"]
        proti = ix["TCP_Protocol"]
        maxcol = max(ti, si, di, spi, dpi, syni, acki, rsti, ttli, proti)

        skipped_proto = 0
        for row in r:
            rows += 1
            if len(row) <= maxcol:
                continue
            if row[proti] != KEEP_PROTO:      # non-TCP rows are not replayed
                skipped_proto += 1
                continue
            try:
                t = float(row[ti])
            except ValueError:
                continue

            is_syn = row[syni] == "Set"
            is_ack = row[acki] == "Set"
            is_rst = row[rsti] == "Set"
            flags = (SYN if is_syn else 0) | (ACK if is_ack else 0) | (RST if is_rst else 0)

            if is_syn and not is_ack:
                pure_syn += 1
            elif is_syn and is_ack:
                syn_ack += 1
            elif is_ack and not is_syn:
                bare_ack += 1

            try:
                srcb = socket.inet_aton(row[si])
                dstb = socket.inet_aton(row[di])
            except OSError:
                bad_ip += 1
                continue

            sport = to_int(row[spi], 0) & 0xFFFF
            dport = to_int(row[dpi], 0) & 0xFFFF
            ttl = to_int(row[ttli], 64) & 0xFF

            frame = build_frame(srcb, dstb, sport, dport, flags, ttl)
            sec = int(t)
            usec = int(round((t - sec) * 1_000_000))
            if usec >= 1_000_000:      # rounding overflow guard
                sec += 1
                usec -= 1_000_000
            writer.write_packet(frame, sec=sec, usec=usec)
            written += 1

            if t > max_t:
                max_t = t
            if min_t is None or t < min_t:
                min_t = t

            if rows % 1_000_000 == 0:
                print(f"    ... {rows:,} rows ({written:,} written) "
                      f"[{rows / (time.time() - t_wall):,.0f} rows/s]", flush=True)

    writer.close()
    dt = time.time() - t_wall
    duration = max_t - (min_t or 0.0)

    def chk(name, got, exp):
        delta = got - exp
        flag = "OK" if delta == 0 else f"DELTA {delta:+,}"
        print(f"  {name:<16} {got:>12,}   expected {exp:>12,}   [{flag}]")

    print("\n" + "=" * 68)
    print("BOUN PCAP BUILD — VERIFICATION")
    print("=" * 68)
    print(f"  output          : {PCAP_PATH}")
    print(f"  size            : {os.path.getsize(PCAP_PATH) / 1e6:,.1f} MB")
    print(f"  build time      : {dt:.1f} s  ({rows / dt:,.0f} rows/s)")
    print("-" * 68)
    chk("total rows read", rows, EXPECT_TOTAL_ROWS)
    chk("frames written", written, EXPECT_TCP_ROWS)
    chk("pureSYN (TCP)", pure_syn, EXPECT_PURE_SYN)
    chk("SYN-ACK (TCP)", syn_ack, EXPECT_SYN_ACK)
    chk("bareACK (TCP)", bare_ack, EXPECT_BARE_ACK)
    print(f"  (probe all-proto tally: pureSYN {PROBE_PURE_SYN:,} / "
          f"SYN-ACK {PROBE_SYN_ACK:,} / bareACK {PROBE_BARE_ACK:,})")
    print("-" * 68)
    print(f"  min_t / max_t   : {min_t:.6f} .. {max_t:.6f} s")
    print(f"  duration        : {duration:.1f} s   (expected ~{EXPECT_DURATION})")
    print(f"  non-TCP rows skipped (UDP/GRE/ICMP/...) : {skipped_proto:,}")
    print(f"  TCP rows with bad/unparsable IP skipped : {bad_ip:,}")
    print(f"  DELTA vs 9,335,605 total = {EXPECT_TOTAL_ROWS - written:+,} "
          f"(all non-TCP frames; carry no SYN/ACK signal)")
    print("=" * 68)

    ok = (written == EXPECT_TCP_ROWS and pure_syn == EXPECT_PURE_SYN
          and syn_ack == EXPECT_SYN_ACK and bare_ack == EXPECT_BARE_ACK)
    print(f"VERIFICATION: {'PASS' if ok else 'CHECK DELTAS ABOVE'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
