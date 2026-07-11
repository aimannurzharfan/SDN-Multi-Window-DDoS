#!/usr/bin/env python3
"""BOUN TCP dataset probe (read-only). Streams the packet-level CSV once and
reports structure needed to design the live-replay experiment."""
import csv, os, sys, statistics, io

REPO = "/home/sdnuser/sdn-thesis"
CSV_PATH = os.path.join(REPO, "datasets", "boun", "BOUN_DDoS dataset", "BOUN_TCP_Anon.csv")
OUT_PATH = os.path.join(REPO, "logs", "boun_probe.txt")

# Documented attack instances (Erhan & Anarim 2020, Data in Brief, Table 1),
# used only for cross-checking the empirically-derived window.
DOC_TABLE = [(1000, 80.22269, 102.20233), (1500, 180.17426, 203.08441),
             (2000, 279.97402, 301.79111), (2500, 380.10981, 402.35755)]

buf = io.StringIO()
def out(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    buf.write(line + "\n")

# ---- Pass over CSV, collect per-second timelines + global sets ----
syn_ps   = {}   # sec -> pure SYN (SYN set, ACK not set)
synack_ps= {}   # sec -> SYN-ACK (SYN set, ACK set)
ack_ps   = {}   # sec -> bare ACK (SYN not set, ACK set)
tot_syn = tot_synack = tot_ack = 0
n = 0
t_first = None; t_last = None
src_all = set()
dst_all = {}

with open(CSV_PATH, newline="") as f:
    r = csv.reader(f)
    header = next(r)
    idx = {c: i for i, c in enumerate(header)}
    iT, iS, iA = idx["Time"], idx["SYN"], idx["ACK"]
    iSrc, iDst = idx["Source_ip"], idx["Destination_IP"]
    for row in r:
        if len(row) <= iA:
            continue
        try:
            t = float(row[iT])
        except ValueError:
            continue
        n += 1
        if t_first is None:
            t_first = t
        t_last = t
        sec = int(t)
        syn = row[iS] == "Set"
        ack = row[iA] == "Set"
        if syn and not ack:
            tot_syn += 1;    syn_ps[sec]    = syn_ps.get(sec, 0) + 1
        elif syn and ack:
            tot_synack += 1; synack_ps[sec] = synack_ps.get(sec, 0) + 1
        elif ack and not syn:
            tot_ack += 1;    ack_ps[sec]    = ack_ps.get(sec, 0) + 1
        src_all.add(row[iSrc])

dur = t_last - t_first
sec_max = int(t_last)

# ---- Empirical attack-window detection from pure-SYN timeline ----
# Baseline from the first 60 s (well before any documented attack).
base_secs = [syn_ps.get(s, 0) for s in range(0, 60)]
base_med = statistics.median(base_secs)
base_mean = statistics.mean(base_secs)
# Elevated = SYN/s above max(5x baseline median, baseline+50). Robust to base~0.
thr = max(5 * base_med, base_med + 50, 30)
elevated = sorted(s for s in range(0, sec_max + 1) if syn_ps.get(s, 0) >= thr)

# Group contiguous elevated seconds into pulses (gap <= 3 s merges).
pulses = []
for s in elevated:
    if pulses and s - pulses[-1][1] <= 3:
        pulses[-1][1] = s
    else:
        pulses.append([s, s])

attack_start_s = elevated[0] if elevated else None
attack_end_s   = elevated[-1] if elevated else None
attack_dur     = (attack_end_s - attack_start_s) if elevated else 0
pre_bg         = attack_start_s - int(t_first) if elevated else None

# Attack membership by union of detected pulses (the real attack traffic).
def in_attack(sec):
    for a, b in pulses:
        if a <= sec <= b:
            return True
    return False
attack_secs = [s for s in range(0, sec_max + 1) if in_attack(s)]
atk_syn_series = [syn_ps.get(s, 0) for s in attack_secs]
mean_atk_pps = statistics.mean(atk_syn_series) if atk_syn_series else 0
peak_atk_pps = max(atk_syn_series) if atk_syn_series else 0

atk_syn    = sum(syn_ps.get(s, 0)    for s in attack_secs)
atk_synack = sum(synack_ps.get(s, 0) for s in attack_secs)
atk_ack    = sum(ack_ps.get(s, 0)    for s in attack_secs)

# ---- Report ----
out("="*72)
out("BOUN TCP DATASET PROBE  (read-only; no Mininet/Ryu)")
out("="*72)
out("File   :", CSV_PATH)
out("Format : packet-level CSV (NOT a .pcap). One row per frame.")
out("Size   : 955 MB   Rows(pkts):", n)
out("")
out("--- SUMMARY TABLE ---")
out(f"{'metric':38s} {'value'}")
out("-"*72)
out(f"{'capture_duration_s':38s} {dur:.3f}")
out(f"{'total_packets':38s} {n}")
out(f"{'baseline_pureSYN_pps (0-60s med/mean)':38s} {base_med:.1f} / {base_mean:.1f}")
out(f"{'elevation_threshold_pps':38s} {thr:.1f}")
out(f"{'attack_start_s (empirical)':38s} {attack_start_s}")
out(f"{'attack_end_s (empirical)':38s} {attack_end_s}")
out(f"{'attack_span_s (end-start, incl gaps)':38s} {attack_dur}")
out(f"{'pre_attack_background_s':38s} {pre_bg}")
out(f"{'attack_mean_SYN_pps (within pulses)':38s} {mean_atk_pps:.1f}")
out(f"{'attack_peak_SYN_pps':38s} {peak_atk_pps}")
out(f"{'total_pureSYN':38s} {tot_syn}")
out(f"{'total_SYNACK':38s} {tot_synack}")
out(f"{'total_bareACK':38s} {tot_ack}")
ratio_all_sa = tot_syn / max(tot_synack, 1)
out(f"{'SYN:SYNACK ratio (overall)':38s} {ratio_all_sa:.3f}")
out(f"{'attack_pureSYN':38s} {atk_syn}")
out(f"{'attack_SYNACK':38s} {atk_synack}")
out(f"{'attack_bareACK':38s} {atk_ack}")
out(f"{'SYN:SYNACK ratio (attack window)':38s} {atk_syn/max(atk_synack,1):.3f}")
out(f"{'unique_src_ip_overall':38s} {len(src_all)}")
out("")

out("--- DETECTED PULSES (contiguous elevated SYN/s, gap<=3s merged) ---")
out(f"{'#':>2} {'start_s':>8} {'end_s':>8} {'dur_s':>6} {'peakSYN/s':>10}")
for i,(a,b) in enumerate(pulses,1):
    pk = max(syn_ps.get(s,0) for s in range(a,b+1))
    out(f"{i:>2} {a:>8} {b:>8} {b-a:>6} {pk:>10}")
out("")
out("Cross-check vs documented Erhan&Anarim 2020 Table 1 (rate, start, end):")
for rate,a,b in DOC_TABLE:
    out(f"   {rate:>5} pps   {a:>9.2f} - {b:>9.2f}   dur={b-a:5.1f}s")
out("")

# ---- Second pass for attack-window unique src IPs + top dst + direction ----
out("--- SECOND PASS: attack-window src/dst + direction ---")
atk_src = set(); atk_dst = {}
# direction: does traffic exist both client->server and server->client?
# Detect by presence of SYN-ACK (server->client) anywhere = bidirectional.
with open(CSV_PATH, newline="") as f:
    r = csv.reader(f)
    next(r)
    for row in r:
        if len(row) <= iA:
            continue
        try:
            t = float(row[iT])
        except ValueError:
            continue
        if in_attack(int(t)):
            atk_src.add(row[iSrc])
            d = row[iDst]
            atk_dst[d] = atk_dst.get(d, 0) + 1

atk_pkts = sum(atk_dst.values())
top_dst = sorted(atk_dst.items(), key=lambda kv: -kv[1])[:3]
out(f"{'unique_src_ip_attack_window':38s} {len(atk_src)}")
out(f"{'unique_src_ip_overall':38s} {len(src_all)}")
out(f"{'attack_window_total_pkts':38s} {atk_pkts}")
out("Top 3 destination IPs in attack window (victim):")
for d,c in top_dst:
    out(f"   {d:20s} {c:>10}  {100*c/max(atk_pkts,1):5.1f}%")
out("")
out("Directionality:")
out(f"   total SYN-ACK (server->client) present overall = {tot_synack}")
out(f"   total SYN-ACK during attack window             = {atk_synack}")
out("   => bidirectional capture" if tot_synack>0 else "   => one-directional only")
out("")

# ---- Four yes/no questions ----
out("="*72)
out("FOUR DECISION QUESTIONS")
out("="*72)
longest_pulse = max((b-a for a,b in pulses), default=0)
out(f"a. attack_duration_s >= 120 ?")
out(f"   longest single pulse       = {longest_pulse}s")
out(f"   full elevated span (80-end)= {attack_dur}s (but contains attack-free gaps)")
out(f"   ANSWER: single sustained attack NO (max pulse {longest_pulse}s < 120);"
    f" contiguous 120s window only possible by treating full span as one event.")
out("")
out(f"b. pre_attack_background_s >= 150 ?")
out(f"   pre_attack_background_s = {pre_bg}s")
out(f"   ANSWER: {'YES' if (pre_bg or 0)>=150 else 'NO'} "
    f"({pre_bg}s {'>=' if (pre_bg or 0)>=150 else '<'} 150)")
out("")
out(f"c. Real SYN-ACK packets during attack window ?")
out(f"   attack_SYNACK = {atk_synack}")
out(f"   ANSWER: {'YES' if atk_synack>0 else 'NO'}")
out("")
out(f"d. Attack source IPs randomised/spoofed ?")
out(f"   unique_src_ip attack window = {len(atk_src)}  vs baseline (0-60s) hosts")
out(f"   ANSWER: (see ratio vs baseline; high unique count => spoofed)")

with open(OUT_PATH, "w") as f:
    f.write(buf.getvalue())
out("")
out("[saved to", OUT_PATH + "]")
