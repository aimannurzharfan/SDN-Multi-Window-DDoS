#!/usr/bin/env python3
"""
drift_live_gen.py — controlled live traffic generator for the LIVE drift study.

Two modes (raw-socket crafted IP/TCP, run as root inside a Mininet host):

  legit : the NON-STATIONARY legitimate baseline. The active source-IP set grows
          linearly from N_LOW to N_HIGH over [DRIFT_START,DRIFT_END]. Sources are
          cycled SYSTEMATICALLY (not random) so each 5 s window sees ~all active
          sources uniformly => source-IP entropy ~= log2(N(t)), a clean rising
          baseline. Each source emits a matched SYN + SYN-ACK (both crafted with
          that source's IP) so synack_ratio stays ~1 (M2 quiet on legit).

  attack: a MODERATE spoofed-SYN burst from a FIXED set of M unique spoofed IPs
          (172.16.x.y, disjoint from legit 10.0.0.x), SYN-only. "Same intensity"
          = same M at every injection point. Adds M unique sources (entropy up)
          and unmatched SYNs (synack_ratio up). M is chosen so early-attack
          entropy ~= late-legit entropy (the drift stress) — see the harness.

All packets go to a single real dst host (closed port => it RSTs; the RST is
RST+ACK, matched by the forwarding offload and dropped, so no reply contaminates
the detector). Source IPs need no ARP (IP_HDRINCL raw send).

Usage:
  drift_live_gen.py legit  <dur> <n_low> <n_high> <drift_start> <drift_end> <pps> <dst>
  drift_live_gen.py attack <dur> <m> <pps> <dst>
"""
import socket, struct, sys, time


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build(src_ip, dst_ip, sport, dport, flags, seq=0):
    ips = socket.inet_aton(src_ip)
    ipd = socket.inet_aton(dst_ip)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, socket.IPPROTO_TCP, 0, ips, ipd)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, socket.IPPROTO_TCP,
                      checksum(iph), ips, ipd)
    ack = (seq + 1) if (flags & 0x10) else 0
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      socket.htons(65535), 0, 0)
    pseudo = struct.pack("!4s4sBBH", ips, ipd, 0, socket.IPPROTO_TCP, len(tcp))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      socket.htons(65535), checksum(pseudo + tcp), 0)
    return iph + tcp


def sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def _send(s, pkt, dst):
    try:
        s.sendto(pkt, (dst, 0))
    except OSError:
        pass


def n_active(elapsed, n_low, n_high, d0, d1):
    if elapsed <= d0:
        return n_low
    if elapsed >= d1:
        return n_high
    return int(round(n_low + (n_high - n_low) * (elapsed - d0) / (d1 - d0)))


def run_legit(dur, n_low, n_high, d0, d1, pps, dst):
    import random
    rng = random.Random()          # time-seeded: natural run-to-run variation
    s = sock()
    t0 = time.time()
    interval = 2.0 / pps           # 2 packets (SYN+SYNACK) per step
    sent = 0
    dport = 80
    # Per-5s-window resampling with jitter so the source-IP entropy carries
    # REALISTIC window-to-window variance (a noiseless baseline gives sigma~0,
    # which would make any fixed threshold fail trivially). Each window draws
    # N_eff ~ N(t)*U(0.85,1.15) source indices (with repeats -> non-uniform
    # counts) from a pool of ~1.3*N(t); OAKF/fixed then compete on a noisy,
    # drifting baseline just like real traffic. Sources stay in 10.10-11.x,
    # disjoint from the 172.16 attack space.
    cur_win, pool, ptr = -1, [], 0
    while time.time() - t0 < dur:
        e = time.time() - t0
        win = int(e // 5)
        if win != cur_win:
            cur_win = win
            Nb = max(2, n_active(e, n_low, n_high, d0, d1))
            n_eff = max(2, int(round(Nb * rng.uniform(0.85, 1.15))))
            span = max(2, int(Nb * 1.3))
            pool = [rng.randrange(span) for _ in range(n_eff)]
            ptr = 0
        idx = pool[ptr % len(pool)]
        ptr += 1
        src = f"10.{10 + (idx >> 8)}.{idx & 255}.1"
        sport = 1024 + (ptr % 60000)
        _send(s, build(src, dst, sport, dport, 0x02, ptr), dst)       # SYN
        _send(s, build(src, dst, dport, sport, 0x12, ptr), dst)       # SYN-ACK (src=src)
        sent += 2
        dt = interval - ((time.time() - t0) - e)
        if dt > 0:
            time.sleep(dt)
    s.close()
    print(f"[drift_live_gen legit] done dur={dur:.0f}s sent={sent} "
          f"N:{n_low}->{n_high}", flush=True)


def run_attack(dur, m, pps, dst):
    s = sock()
    t0 = time.time()
    interval = 1.0 / pps
    i = 0
    sent = 0
    while time.time() - t0 < dur:
        e = time.time() - t0
        j = i % m
        src = f"172.16.{(j >> 8) & 255}.{(j & 255)}"     # fixed set of M spoofed IPs
        sport = 1024 + (i % 60000)
        _send(s, build(src, dst, sport, 80, 0x02, i + 1), dst)          # spoofed SYN
        sent += 1
        i += 1
        dt = interval - ((time.time() - t0) - e)
        if dt > 0:
            time.sleep(dt)
    s.close()
    print(f"[drift_live_gen attack] done dur={dur:.0f}s sent={sent} M={m}", flush=True)


def main():
    mode = sys.argv[1]
    if mode == "legit":
        _, _, dur, nl, nh, d0, d1, pps, dst = sys.argv
        run_legit(float(dur), int(nl), int(nh), float(d0), float(d1), float(pps), dst)
    elif mode == "attack":
        _, _, dur, m, pps, dst = sys.argv
        run_attack(float(dur), int(m), float(pps), dst)
    else:
        print("usage: drift_live_gen.py legit|attack ...")
        sys.exit(1)


if __name__ == "__main__":
    main()
