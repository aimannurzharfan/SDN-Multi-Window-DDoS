#!/usr/bin/env python3
"""
recompute_boun_labels.py — corrected pulse labelling for a BOUN live replay.

The live replay could NOT hold native timing: the saturated controller
back-pressured OVS, which back-pressured tcpreplay, so the 482.7 s pcap took
~717 s to send and the stretch is non-uniform (faster early, ~2.5x slower late).
Mapping a detector cycle's wall time directly to BOUN time (wall - t_replay) is
therefore wrong.

This script reconstructs the true wall->BOUN map from tcpreplay's own --stats
output: each "Actual: N packets sent in T seconds" line ties wall-elapsed T to
the BOUN timestamp of the N-th replayed packet (packets are sent in pcap order).
We then relabel every detector cycle by its corrected BOUN span and recompute
DR / FPR exactly as eval_boun.py does.

Usage:
    python3 harness/scripts/recompute_boun_labels.py <detector_csv> <tcpreplay_log>
"""

import bisect
import csv
import os
import re
import statistics
import sys
from datetime import datetime

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CSV_PATH = os.path.join(REPO, "datasets", "boun", "BOUN_DDoS dataset", "BOUN_TCP_Anon.csv")

ATTACK_TABLE = [
    (1000, 80.22269, 102.20233),
    (1500, 180.17426, 203.08441),
    (2000, 279.97402, 301.79111),
    (2500, 380.10981, 402.35755),
]
FIRST_ATTACK_START = min(a[1] for a in ATTACK_TABLE)
ATTACK_LABEL_OVERLAP = 0.5
WINDOW_SIZES = (5, 30, 120)
NAME_TO_SIZE = {"5s": 5, "30s": 30, "120s": 120}


def label_window(start, end):
    size = end - start
    best_frac, best_rate, any_overlap = 0.0, None, False
    for rate, a0, a1 in ATTACK_TABLE:
        ov = max(0.0, min(end, a1) - max(start, a0))
        if ov > 0:
            any_overlap = True
        frac = ov / size if size > 0 else 0.0
        if frac > best_frac:
            best_frac, best_rate = frac, rate
    if best_frac >= ATTACK_LABEL_OVERLAP:
        return "attack", best_rate
    if any_overlap:
        return "boundary", None
    return "legit", None


def load_tcp_times():
    """BOUN Time of every replayed (TCP) packet, in pcap order."""
    times = []
    with open(CSV_PATH, newline="") as f:
        r = csv.reader(f)
        h = next(r)
        ix = {n: i for i, n in enumerate(h)}
        ti, proti = ix["Time"], ix["TCP_Protocol"]
        for row in r:
            if len(row) <= proti or row[proti] != "TCP":
                continue
            try:
                times.append(float(row[ti]))
            except ValueError:
                pass
    return times


def parse_stats(log_path):
    """Return (test_start_epoch, [(wall_T, packets_N), ...]) from tcpreplay log."""
    test_start = None
    pts = [(0.0, 0)]
    with open(log_path, errors="replace") as f:
        for line in f:
            s = line.strip()
            m = re.match(r"Test start:\s*([\d\-]+ [\d:\.]+)", s)
            if m:
                test_start = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f").timestamp()
            m = re.match(r"Actual:\s*(\d+)\s*packets.*sent in ([\d.]+)\s*seconds", s)
            if m:
                pts.append((float(m.group(2)), int(m.group(1))))
    pts = sorted(set(pts))
    return test_start, pts


def build_wall_to_boun(pts, ptime):
    """Piecewise-linear wall_elapsed -> BOUN time, via packets-sent as the bridge."""
    walls = [w for w, _ in pts]
    bouns = []
    for _, n in pts:
        idx = min(max(n - 1, 0), len(ptime) - 1)
        bouns.append(ptime[idx])
    bouns[0] = 0.0

    def f(wall):
        if wall <= walls[0]:
            return bouns[0]
        if wall >= walls[-1]:
            return bouns[-1]
        i = bisect.bisect_right(walls, wall) - 1
        w0, w1 = walls[i], walls[i + 1]
        b0, b1 = bouns[i], bouns[i + 1]
        if w1 == w0:
            return b1
        return b0 + (b1 - b0) * (wall - w0) / (w1 - w0)

    return f


def fmt_pct(h, t):
    return "   n/a" if t == 0 else f"{100.0 * h / t:6.2f}%"


def analyze(det_csv, tr_log):
    """Return {size: [cycle-records]} with corrected BOUN spans + labels.

    Shared by this script's __main__ and experiment_boun.py so the live harness
    scores with the same stats-based wall->BOUN mapping (never the naive one).
    """
    ptime = load_tcp_times()
    test_start, pts = parse_stats(tr_log)
    wall2boun = build_wall_to_boun(pts, ptime)
    rows = list(csv.DictReader(open(det_csv, newline="")))
    per = {s: [] for s in WINDOW_SIZES}
    for r in rows:
        size = NAME_TO_SIZE.get(r["window"])
        if size is None:
            continue
        wall_end = float(r["timestamp"]) - test_start
        wall_start = wall_end - size
        if wall_end <= 0:
            continue
        boun_end = wall2boun(wall_end)
        boun_start = wall2boun(wall_start)
        is_calib = boun_end <= FIRST_ATTACK_START
        label, rate = label_window(boun_start, boun_end)
        per[size].append({
            "boun_start": boun_start, "boun_end": boun_end,
            "phase": "calibration" if is_calib else "eval",
            "label": label, "rate": rate,
            "entropy": float(r["entropy"]), "revisit": float(r["revisit"]),
            "synack": float(r["synack_ratio"]),
            "syn": int(r["syn"]), "synA": int(r["synack"]),
            "packets": int(r["packets"]), "uniq": int(r["unique_ips"]),
            "M1": int(r["mech1"]), "M2": int(r["mech2"]), "alert": int(r["alert"]),
            "proc": float(r["proc_time_ms"]),
        })
    return per


def main():
    det_csv = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "logs", "boun", "run_boun_chunk_0_FULL.csv")
    tr_log = sys.argv[2] if len(sys.argv) > 2 else os.path.join(REPO, "logs", "boun", "tcpreplay_boun.log")

    print("[recompute] loading TCP packet times + tcpreplay stats ...", flush=True)
    per = analyze(det_csv, tr_log)

    print("\n" + "=" * 82)
    print("CORRECTED DETECTION (stats-based wall->BOUN mapping)")
    print("=" * 82)
    print(f"  {'window':>7} {'calib':>6} {'attackW':>8} {'legitW':>7} {'bound':>6} "
          f"{'DR':>9} {'FPR':>9} {'meanProc':>10}")
    for size in WINDOW_SIZES:
        recs = per[size]
        ev = [x for x in recs if x["phase"] == "eval"]
        calib = [x for x in recs if x["phase"] == "calibration"]
        atk = [x for x in ev if x["label"] == "attack"]
        leg = [x for x in ev if x["label"] == "legit"]
        bnd = [x for x in ev if x["label"] == "boundary"]
        drh = sum(x["alert"] for x in atk)
        fph = sum(x["alert"] for x in leg)
        proc = [x["proc"] for x in recs]
        print(f"  {str(size)+'s':>7} {len(calib):>6} {len(atk):>8} {len(leg):>7} "
              f"{len(bnd):>6} {fmt_pct(drh, len(atk)):>9} {fmt_pct(fph, len(leg)):>9} "
              f"{statistics.mean(proc) if proc else 0:>8.2f}ms")

    # M1/M2 breakdown on attack windows (5s) — did each mechanism fire?
    for size in (5, 30):
        recs = per[size]
        atk = [x for x in recs if x["label"] == "attack"]
        if not atk:
            continue
        m1 = sum(x["M1"] for x in atk)
        m2 = sum(x["M2"] for x in atk)
        al = sum(x["alert"] for x in atk)
        print(f"\n  [{size}s] attack windows={len(atk)}: M1 fired={m1}  M2 fired={m2}  "
              f"alert(M1&M2)={al}")

    # Corrected sanity dump: calibration + true pulse cycles (5s and 30s).
    for size in (5, 30):
        recs = sorted(per[size], key=lambda x: x["boun_start"])
        print(f"\n[ CORRECTED SANITY DUMP — {size}s window ]")
        print(f"  {'boun_t':>13} {'label':>7} {'rate':>5} {'entropy':>8} {'revisit':>9} "
              f"{'synack':>9} {'syn':>7} {'synA':>6} {'pkts':>7} {'M1':>3} {'M2':>3} {'AL':>3}")
        calib = [x for x in recs if x["phase"] == "calibration"]
        atk_idx = [i for i, x in enumerate(recs) if x["label"] == "attack"]
        picks, seen = [], set()
        step = max(1, len(calib) // 4)
        for x in calib[::step][:4]:
            picks.append(x); seen.add(id(x))
        for i in atk_idx:
            for j in (i - 1, i, i + 1):
                if 0 <= j < len(recs) and id(recs[j]) not in seen:
                    picks.append(recs[j]); seen.add(id(recs[j]))
        for x in sorted(picks, key=lambda r: r["boun_start"]):
            print(f"  {x['boun_start']:6.1f}-{x['boun_end']:<6.1f} {x['label'][:7]:>7} "
                  f"{str(x['rate'] or '-'):>5} {x['entropy']:8.3f} {x['revisit']:9.2f} "
                  f"{x['synack']:9.2f} {x['syn']:7d} {x['synA']:6d} {x['packets']:7d} "
                  f"{'Y' if x['M1'] else '.':>3} {'Y' if x['M2'] else '.':>3} "
                  f"{'Y' if x['alert'] else '.':>3}")


if __name__ == "__main__":
    main()
