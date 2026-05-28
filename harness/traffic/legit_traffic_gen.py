#!/usr/bin/env python3
"""
Legitimate traffic generator for SDN experiment calibration phase.

Generates low-rate, balanced TCP traffic between Mininet host pairs so
the OAKF can establish a stable baseline before attack injection.

Traffic profile (designed to keep signals in the "normal" range):
  - Source IP pool: 20 distinct hosts (the Mininet hosts themselves)
  - Rate:           ~20 pps total (10 SYN + 10 SYN-ACK/s)
  - SYN : SYNACK ratio ~ 1 : 1  (balanced handshake simulation)
  - Revisit ratio: ~2-5 (each IP sends a few packets per window)
  - Entropy: ~3.0-4.0 bits (20 IPs, approximately uniform)

Usage (run as root inside Mininet CLI or via mn --run):
    python3 legit_traffic_gen.py <duration_seconds>

    E.g.: python3 legit_traffic_gen.py 150

The script uses raw sockets so it works on any host with Python 3.
It sends crafted IP/TCP packets directly — no Mininet Python API needed.
Run it on any Mininet host that has been assigned to send traffic.

For the experiment harness, experiment.py spawns this on h1 inside
Mininet's network namespace via start_legit_traffic().

The generated packets traverse the OpenFlow switches and reach Ryu as
packet_in events, creating the baseline signal the OAKF trains on.
"""

import random
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Host IP pool (matches tree_5sw_20h.py — 10.0.0.1 through 10.0.0.20)
# ---------------------------------------------------------------------------
HOST_IPS = [f"10.0.0.{i}" for i in range(1, 21)]

# Destination ports for simulated services (HTTP, HTTPS, SSH, DNS, SMTP)
DST_PORTS = [80, 443, 22, 53, 25, 8080, 3306, 5432]

# Target overall rate and inter-packet interval
RATE_PPS     = 20
INTERVAL_S   = 1.0 / RATE_PPS


# ---------------------------------------------------------------------------
# Raw packet helpers
# ---------------------------------------------------------------------------

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_tcp_packet(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     flags: int, seq: int = 0) -> bytes:
    """Build a raw IP/TCP packet. flags: 0x02=SYN, 0x12=SYN+ACK."""

    # IP header (no options)
    ip_ihl_ver  = (4 << 4) | 5
    ip_tos      = 0
    ip_tot_len  = 40          # 20 IP + 20 TCP
    ip_id       = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl      = 64
    ip_proto    = socket.IPPROTO_TCP
    ip_check    = 0
    ip_src      = socket.inet_aton(src_ip)
    ip_dst      = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_src, ip_dst,
    )
    ip_check = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_src, ip_dst,
    )

    # TCP header
    tcp_doff    = 5 << 4
    tcp_window  = socket.htons(65535)
    tcp_check   = 0
    tcp_urg_ptr = 0
    ack_seq     = (seq + 1) if (flags & 0x10) else 0  # ACK number if SYN+ACK

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        tcp_doff, flags, tcp_window, tcp_check, tcp_urg_ptr,
    )

    # Pseudo-header for checksum
    pseudo = struct.pack("!4s4sBBH", ip_src, ip_dst, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_check = checksum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        tcp_doff, flags, tcp_window, tcp_check, tcp_urg_ptr,
    )

    return ip_header + tcp_header


def send_packet(sock: socket.socket, dst_ip: str, pkt: bytes):
    try:
        sock.sendto(pkt, (dst_ip, 0))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Traffic generation loop
# ---------------------------------------------------------------------------

def generate_traffic(duration_s: float):
    """
    Send balanced SYN / SYN-ACK pairs to simulate normal TCP traffic.
    Alternates between hosts to keep per-IP packet counts low and
    source entropy high.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[legit_traffic_gen] ERROR: must run as root", flush=True)
        sys.exit(1)

    deadline = time.time() + duration_s
    sent = 0
    seq = random.randint(1000, 2**31)

    print(
        f"[legit_traffic_gen] Starting {duration_s:.0f}s of legitimate traffic "
        f"at ~{RATE_PPS} pps from {len(HOST_IPS)} IPs",
        flush=True,
    )

    while time.time() < deadline:
        t_iter = time.time()

        # Pick a random src/dst pair (different hosts)
        src_ip  = random.choice(HOST_IPS)
        dst_ip  = random.choice([ip for ip in HOST_IPS if ip != src_ip])
        sport   = random.randint(1024, 65535)
        dport   = random.choice(DST_PORTS)
        seq    += 1

        # Send SYN from src to dst
        syn_pkt = build_tcp_packet(src_ip, dst_ip, sport, dport, 0x02, seq)
        send_packet(sock, dst_ip, syn_pkt)
        sent += 1

        # Immediately send SYN-ACK from dst back to src (simulate server reply)
        # This keeps synack_ratio ~ 1.0 for the detector.
        synack_pkt = build_tcp_packet(dst_ip, src_ip, dport, sport, 0x12, seq + 100)
        send_packet(sock, src_ip, synack_pkt)
        sent += 1

        # Pace to RATE_PPS (each loop sends 2 packets, so effective rate
        # per loop is RATE_PPS / 2 loops/s).
        elapsed = time.time() - t_iter
        sleep_t = (INTERVAL_S * 2) - elapsed
        if sleep_t > 0:
            time.sleep(sleep_t)

    sock.close()
    elapsed_total = duration_s
    actual_pps = sent / elapsed_total if elapsed_total > 0 else 0
    print(
        f"[legit_traffic_gen] Done. sent={sent} pkts, "
        f"actual_rate={actual_pps:.0f} pps",
        flush=True,
    )


if __name__ == "__main__":
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 150.0
    generate_traffic(dur)
