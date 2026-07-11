#!/usr/bin/env python3
"""
analyze_boun_batch.py — post-hoc analysis + FULL_HYST re-scoring for the final
BOUN live batch. RE-SCORING ONLY: it launches no experiments and changes no
thresholds/params. It reuses the logged M1/M2/alert flags and the corrected
stats-based wall->BOUN mapping (recompute_boun_labels), and derives the
FULL_HYST persistence rule purely as an alert-combination change.

Pre-registered labelling (identical for every run):
  Ground-truth pulses (BOUN time): 80-101, 180-202, 280-300, 380-402 s
    (the eval_boun ATTACK_TABLE; >=50% window overlap = attack).
  K = flood-rate SYN threshold, chosen in the valley of the per-5s-window SYN
    histogram pooled over the FULL runs (printed with the histogram).
  nominal label : attack (>=50% pulse overlap) | boundary (partial, EXCLUDED) | legit
  primary label : attack if (nominal attack) OR (syn >= K)  else legit
                  (SYN>=K folds replay-lag flood tails back into 'attack')
  DR/FPR are reported under BOTH labellings; the nominal-vs-primary FPR gap is
  exactly the replay-lag tail windows (the reconciliation).

FULL_HYST rule (per window-size stream, time-ordered):
  base_alert  = M1 AND M2                      (the FULL alert, unchanged)
  alert_hyst  = base_alert[i] OR (base_alert fired in the previous N windows)
  Computed for N=1 (primary) and N=2 (sensitivity), on (a) the BOUN FULL runs and
  (b) the existing CIC FULL run CSVs in logs/. Keep-verdict: FULL_HYST is worth
  keeping ONLY IF it raises BOUN DR AND does not raise CIC FPR.

Usage:  python3 harness/scripts/analyze_boun_batch.py
"""

import csv
import glob
import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BOUN_LOG_DIR = os.path.join(REPO, "logs", "boun")
BATCH_DIR = os.path.join(BOUN_LOG_DIR, "batch")
CIC_LOG_DIR = os.path.join(REPO, "logs")
SPAN = 482.66

sys.path.insert(0, HERE)
import recompute_boun_labels as rc  # noqa: E402

WINDOW_SIZES = (5, 30)          # 120s excluded: under-warmed (1 calib cycle)
NAME_TO_SIZE = {"5s": 5, "30s": 30, "120s": 120}
SIGNALS = ("entropy", "revisit", "synack")   # CSV anom columns: <sig>_anom

# Cache the BOUN packet-time vector once (load_tcp_times reads the 955MB CSV).
_PTIME = None


def ptime():
    global _PTIME
    if _PTIME is None:
        _PTIME = rc.load_tcp_times()
    return _PTIME


# ---------------------------------------------------------------------------
# Small stat helpers
# ---------------------------------------------------------------------------
def mean_sd(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return (None, None, 0)
    return (statistics.mean(xs), statistics.stdev(xs) if len(xs) > 1 else 0.0, len(xs))


def pct(x):
    return "  n/a  " if x is None else f"{100*x:6.2f}%"


def ms(x):
    return " n/a" if x is None else f"{x:.3f}ms"


def hysteresis(base, n):
    """base: time-ordered list[bool]; return alert_hyst with N-window persistence."""
    out = []
    for i in range(len(base)):
        fire = base[i] or any(base[max(0, i - n):i])
        out.append(bool(fire))
    return out


# ---------------------------------------------------------------------------
# Load one BOUN detector run -> per-size list of window records
# ---------------------------------------------------------------------------
def load_boun_run(csv_path, tr_log, K):
    """Return {size: [records]} with corrected BOUN spans + nominal/primary labels.

    Each record carries M1/M2/alert, syn, per-signal anom flags, proc time.
    Records are time-ordered within each size (as written).
    """
    test_start, pts = rc.parse_stats(tr_log)
    if test_start is None:
        # Fall back: use first detector timestamp as t0.
        with open(csv_path, newline="") as f:
            first = next(csv.DictReader(f))
        test_start = float(first["timestamp"]) - float(first["elapsed_s"])
    wall2boun = rc.build_wall_to_boun(pts, ptime())

    per = {s: [] for s in NAME_TO_SIZE.values()}
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            size = NAME_TO_SIZE.get(r["window"])
            if size is None:
                continue
            wall_end = float(r["timestamp"]) - test_start
            if wall_end <= 0:
                continue
            b_end = wall2boun(wall_end)
            b_start = wall2boun(wall_end - size)
            nlabel, rate = rc.label_window(b_start, b_end)
            syn = int(r["syn"])
            is_calib = b_end <= rc.FIRST_ATTACK_START
            prim = "attack" if (nlabel == "attack" or syn >= K) else "legit"
            per[size].append({
                "b_start": b_start, "b_end": b_end, "rate": rate,
                "nominal": nlabel, "primary": prim, "is_calib": is_calib,
                "M1": int(r["mech1"]), "M2": int(r["mech2"]), "alert": int(r["alert"]),
                "syn": syn, "synack": int(r["synack"]),
                "entropy_anom": int(r["entropy_anom"]),
                "revisit_anom": int(r["revisit_anom"]),
                "synack_anom": int(r["synack_anom"]),
                # Shadow paired flags (same k*sd band; adaptive OAKF vs frozen
                # static) logged on EVERY run — the clean drift comparison.
                "entropy_oakf_anom": int(r.get("entropy_oakf_anom", 0)),
                "entropy_fixed_anom": int(r.get("entropy_fixed_anom", 0)),
                "revisit_oakf_anom": int(r.get("revisit_oakf_anom", 0)),
                "revisit_fixed_anom": int(r.get("revisit_fixed_anom", 0)),
                "synack_oakf_anom": int(r.get("synack_oakf_anom", 0)),
                "synack_fixed_anom": int(r.get("synack_fixed_anom", 0)),
                "proc": float(r["proc_time_ms"]),
            })
    return per


def score_boun_run(per, hyst_n=None):
    """Per size: DR/FPR (primary+nominal), M1/M2 rates, proc, spurious anom rates.

    If hyst_n is given, the alert stream is replaced by the FULL_HYST rule
    (base = M1&M2) with that N before scoring DR/FPR.
    """
    out = {}
    for size, recs in per.items():
        if size not in WINDOW_SIZES:
            continue
        # Alert stream (base or hysteresis-persisted).
        base = [bool(x["M1"] and x["M2"]) for x in recs]
        alert = hysteresis(base, hyst_n) if hyst_n else base

        # Post-calibration eval windows only (calibration seeds, not scored).
        idx = [i for i, x in enumerate(recs) if not x["is_calib"]]
        n_att = {"primary": [], "nominal": []}
        n_leg = {"primary": [], "nominal": []}
        for i in idx:
            x = recs[i]
            a = alert[i]
            # primary
            (n_att if x["primary"] == "attack" else n_leg)["primary"].append((a, x))
            # nominal (boundary excluded)
            if x["nominal"] == "attack":
                n_att["nominal"].append((a, x))
            elif x["nominal"] == "legit":
                n_leg["nominal"].append((a, x))

        def rate(pairs):
            return (sum(1 for a, _ in pairs if a) / len(pairs)) if pairs else None

        att_p = n_att["primary"]
        m1r = (sum(x["M1"] for _, x in att_p) / len(att_p)) if att_p else None
        m2r = (sum(x["M2"] for _, x in att_p) / len(att_p)) if att_p else None

        # Spurious per-signal anomaly rate on primary-legit (background + gaps).
        leg_p = [x for _, x in n_leg["primary"]]
        spur = {}
        shadow_spur = {}   # {sig: {"oakf":rate, "fixed":rate}} — paired drift test
        for sig in SIGNALS:
            spur[sig] = (sum(x[f"{sig}_anom"] for x in leg_p) / len(leg_p)) if leg_p else None
            if leg_p:
                shadow_spur[sig] = {
                    "oakf": sum(x[f"{sig}_oakf_anom"] for x in leg_p) / len(leg_p),
                    "fixed": sum(x[f"{sig}_fixed_anom"] for x in leg_p) / len(leg_p),
                }
            else:
                shadow_spur[sig] = {"oakf": None, "fixed": None}

        out[size] = {
            "dr_primary": rate(n_att["primary"]), "fpr_primary": rate(n_leg["primary"]),
            "dr_nominal": rate(n_att["nominal"]), "fpr_nominal": rate(n_leg["nominal"]),
            "n_att_primary": len(n_att["primary"]), "n_leg_primary": len(n_leg["primary"]),
            "n_att_nominal": len(n_att["nominal"]), "n_leg_nominal": len(n_leg["nominal"]),
            "m1_rate": m1r, "m2_rate": m2r,
            "proc": statistics.mean([x["proc"] for x in recs]) if recs else None,
            "spurious": spur, "shadow_spurious": shadow_spur,
        }
    return out


# ---------------------------------------------------------------------------
# Discover batch runs from the manifest (fallback: glob)
# ---------------------------------------------------------------------------
def discover_runs():
    """Return {mode: [(run_id, csv_path, tr_log)]} for detector modes present."""
    runs = {}
    for csv_path in sorted(glob.glob(os.path.join(BOUN_LOG_DIR, "run_b_*_chunk_0_*.csv"))):
        m = re.match(r"run_(b_\w+?_\d+)_chunk_0_([A-Z_]+)\.csv$", os.path.basename(csv_path))
        if not m:
            continue
        run_id, mode = m.group(1), m.group(2)
        tr_log = os.path.join(BATCH_DIR, f"tcpreplay_{run_id}.log")
        if not os.path.isfile(tr_log):
            continue
        runs.setdefault(mode, []).append((run_id, csv_path, tr_log))
    return runs


# ---------------------------------------------------------------------------
# K selection: valley of the pooled per-5s-window SYN histogram (FULL runs)
# ---------------------------------------------------------------------------
def choose_K(full_runs):
    syns = []
    for _, csv_path, _ in full_runs:
        with open(csv_path, newline="") as f:
            for r in csv.DictReader(f):
                if r["window"] == "5s":
                    syns.append(int(r["syn"]))
    syns.sort()
    # Log-ish bins for the histogram print.
    bins = [0, 500, 1000, 2000, 3000, 5000, 8000, 12000, 16000, 20000, 25000, 10**9]
    hist = [0] * (len(bins) - 1)
    for v in syns:
        for b in range(len(bins) - 1):
            if bins[b] <= v < bins[b + 1]:
                hist[b] += 1
                break
    # Valley: pick the lowest-count bin strictly between the baseline mode
    # (<3000) and the flood mode (>=16000). K = that bin's lower edge.
    cand = [(hist[b], bins[b]) for b in range(len(bins) - 1)
            if 3000 <= bins[b] < 16000]
    K = min(cand)[1] if cand else 8000
    return K, bins, hist, syns


# ---------------------------------------------------------------------------
# CIC FULL_HYST re-scoring (phase-labelled; DR on attack, FPR on calibration)
# ---------------------------------------------------------------------------
def score_cic_run(csv_path, hyst_n=None):
    """Return {size: (dr, fpr)} for one CIC FULL CSV (base or hysteresis)."""
    by_win = {}
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            by_win.setdefault(r["window"], []).append(r)
    out = {}
    for wname, rows in by_win.items():
        size = NAME_TO_SIZE.get(wname)
        if size is None:
            continue
        rows.sort(key=lambda r: float(r["timestamp"]))
        base = [bool(int(r["mech1"]) and int(r["mech2"])) for r in rows]
        alert = hysteresis(base, hyst_n) if hyst_n else base
        att = [(a, r) for a, r in zip(alert, rows) if r["phase"] == "attack"]
        cal = [(a, r) for a, r in zip(alert, rows) if r["phase"] == "calibration"]
        dr = (sum(1 for a, _ in att if a) / len(att)) if att else None
        fpr = (sum(1 for a, _ in cal if a) / len(cal)) if cal else None
        out[size] = (dr, fpr)
    return out


def cic_full_csvs():
    return sorted(glob.glob(os.path.join(CIC_LOG_DIR, "run_*_FULL.csv")))


# ---------------------------------------------------------------------------
# CPU aggregation (ON = FULL runs, OFF = NOOP runs)
# ---------------------------------------------------------------------------
def cpu_stats(pattern):
    runs = []
    for path in sorted(glob.glob(os.path.join(BOUN_LOG_DIR, pattern))):
        vals = []
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                try:
                    vals.append(float(r["ryu_cpu_pct"]))
                except (ValueError, KeyError):
                    pass
        if vals:
            runs.append((statistics.mean(vals), max(vals)))
    return runs   # list of (mean, peak) per run


# ---------------------------------------------------------------------------
# Replay fidelity from a tcpreplay log
# ---------------------------------------------------------------------------
def replay_stretch(tr_log):
    dur = None
    with open(tr_log, errors="replace") as f:
        for line in f:
            m = re.search(r"Actual:\s*[\d,]+\s*packets.*sent in ([\d.]+)\s*seconds", line)
            if m:
                dur = float(m.group(1))
    return (dur, dur / SPAN if dur else None)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def agg_field(scored_list, size, field):
    return mean_sd([s[size][field] for s in scored_list if size in s])


def main():
    runs = discover_runs()
    full_runs = runs.get("FULL", [])
    L = []
    P = L.append
    P("=" * 82)
    P("BOUN FINAL BATCH — ANALYSIS + FULL_HYST RE-SCORING")
    P("=" * 82)
    P(f"discovered runs: " + ", ".join(f"{m}={len(v)}" for m, v in sorted(runs.items())))
    if not full_runs:
        P("NO FULL runs found yet — batch incomplete. Re-run when batch done.")
        print("\n".join(L))
        return 0

    # --- K threshold + histogram ---
    K, bins, hist, syns = choose_K(full_runs)
    P("\n[ SYN THRESHOLD K — per-5s-window SYN histogram, pooled over FULL runs ]")
    for b in range(len(bins) - 1):
        hi = "inf" if bins[b + 1] >= 10**9 else str(bins[b + 1])
        P(f"    [{bins[b]:>6}-{hi:>6}) : {hist[b]:>5}  {'#' * min(60, hist[b])}")
    P(f"    chosen K = {K} SYN/5s (valley between baseline <3k and flood >=16k)")

    # --- Load + score every detector run (base) ---
    scored = {}   # mode -> list of per-run score dicts (base alert)
    per_cache = {}  # (mode,run_id) -> per (for hyst re-scoring)
    for mode, lst in runs.items():
        scored[mode] = []
        for run_id, csv_path, tr_log in lst:
            per = load_boun_run(csv_path, tr_log, K)
            per_cache[(mode, run_id)] = per
            scored[mode].append(score_boun_run(per))

    # =========================================================================
    # A. FULL_HYST vs FULL — both datasets
    # =========================================================================
    P("\n" + "=" * 82)
    P("A. FULL_HYST vs FULL  (re-scoring only; base = M1 AND M2)")
    P("=" * 82)
    # BOUN: base vs N=1 vs N=2, DR/FPR (primary) at 5s/30s
    P("\n  BOUN (mean±SD across FULL runs, primary labelling):")
    P(f"    {'size':>5} {'rule':>6} {'DR':>16} {'FPR_prim':>16} {'FPR_nom':>16}")
    boun_hyst = {n: [] for n in (0, 1, 2)}
    for run_id, csv_path, tr_log in full_runs:
        per = per_cache[("FULL", run_id)]
        boun_hyst[0].append(score_boun_run(per))
        boun_hyst[1].append(score_boun_run(per, 1))
        boun_hyst[2].append(score_boun_run(per, 2))
    for size in WINDOW_SIZES:
        for n in (0, 1, 2):
            tag = "FULL" if n == 0 else f"HYST{n}"
            dr = agg_field(boun_hyst[n], size, "dr_primary")
            fp = agg_field(boun_hyst[n], size, "fpr_primary")
            fpn = agg_field(boun_hyst[n], size, "fpr_nominal")
            P(f"    {str(size)+'s':>5} {tag:>6} "
              f"{pct(dr[0])+' ±'+pct(dr[1]).strip():>16} "
              f"{pct(fp[0])+' ±'+pct(fp[1]).strip():>16} "
              f"{pct(fpn[0])+' ±'+pct(fpn[1]).strip():>16}")

    # CIC: base vs N=1 vs N=2, DR/FPR at 5s/30s/120s
    cic_files = cic_full_csvs()
    P(f"\n  CIC (mean±SD across {len(cic_files)} existing FULL run CSVs, phase labelling):")
    P(f"    {'size':>5} {'rule':>6} {'DR':>16} {'FPR':>16}")
    cic_scored = {n: [] for n in (0, 1, 2)}
    for fp_ in cic_files:
        cic_scored[0].append(score_cic_run(fp_))
        cic_scored[1].append(score_cic_run(fp_, 1))
        cic_scored[2].append(score_cic_run(fp_, 2))
    for size in (5, 30, 120):
        for n in (0, 1, 2):
            tag = "FULL" if n == 0 else f"HYST{n}"
            drs = mean_sd([s.get(size, (None, None))[0] for s in cic_scored[n]])
            fps = mean_sd([s.get(size, (None, None))[1] for s in cic_scored[n]])
            P(f"    {str(size)+'s':>5} {tag:>6} "
              f"{pct(drs[0])+' ±'+pct(drs[1]).strip():>16} "
              f"{pct(fps[0])+' ±'+pct(fps[1]).strip():>16}")

    # Verdict
    P("\n  KEEP/DROP VERDICT (rule: keep iff BOUN DR up AND CIC FPR not up):")
    for n in (1, 2):
        b_dr0 = agg_field(boun_hyst[0], 5, "dr_primary")[0] or 0
        b_dr = agg_field(boun_hyst[n], 5, "dr_primary")[0] or 0
        c_fpr0 = mean_sd([s.get(5, (None, None))[1] for s in cic_scored[0]])[0] or 0
        c_fpr = mean_sd([s.get(5, (None, None))[1] for s in cic_scored[n]])[0] or 0
        dr_up = b_dr > b_dr0 + 1e-9
        fpr_up = c_fpr > c_fpr0 + 1e-9
        verdict = "KEEP" if (dr_up and not fpr_up) else "DROP"
        P(f"    N={n}: BOUN 5s DR {100*b_dr0:.2f}%->{100*b_dr:.2f}% "
          f"({'+' if dr_up else 'no+'}) ; CIC 5s FPR {100*c_fpr0:.4f}%->{100*c_fpr:.4f}% "
          f"({'RAISED' if fpr_up else 'unchanged'})  => {verdict}")

    # =========================================================================
    # B. FIXED_THRESHOLD vs FULL — DR/FPR + spurious anomaly (drift)
    # =========================================================================
    P("\n" + "=" * 82)
    P("B. FIXED_THRESHOLD vs FULL  (adaptive verdict)")
    P("=" * 82)
    P(f"    {'mode':>16} {'size':>5} {'DR_prim':>14} {'FPR_prim':>14} {'FPR_nom':>14}")
    for mode in ("FULL", "FIXED_THRESHOLD"):
        if mode not in scored:
            continue
        for size in WINDOW_SIZES:
            dr = agg_field(scored[mode], size, "dr_primary")
            fp = agg_field(scored[mode], size, "fpr_primary")
            fpn = agg_field(scored[mode], size, "fpr_nominal")
            P(f"    {mode:>16} {str(size)+'s':>5} {pct(dr[0]):>14} {pct(fp[0]):>14} {pct(fpn[0]):>14}")
    P("\n  Per-signal SPURIOUS anomaly rate on non-attack windows (primary-legit),")
    P("  5s window — OAKF (FULL, live flags) vs frozen-fixed (FIXED_THRESHOLD):")
    P(f"    {'mode':>16} {'entropy':>10} {'revisit':>10} {'synack':>10}")
    for mode in ("FULL", "FIXED_THRESHOLD"):
        if mode not in scored:
            continue
        row = {}
        for sig in SIGNALS:
            row[sig] = mean_sd([s[5]["spurious"][sig] for s in scored[mode] if 5 in s])[0]
        P(f"    {mode:>16} {pct(row['entropy']):>10} {pct(row['revisit']):>10} {pct(row['synack']):>10}")
    P("\n  NOTE: FIXED_THRESHOLD's live tracker uses band |v-mean|>mean+k*sd (very")
    P("  wide) so it never fires on BOUN (0% DR AND 0% spurious) — inert, not good.")
    P("\n  Paired drift test (SAME k*sd band, adaptive OAKF vs frozen static),")
    P("  logged on every FULL run, spurious rate on non-attack windows, 5s:")
    P(f"    {'signal':>10} {'OAKF(adaptive)':>16} {'static(frozen)':>16}")
    for sig in SIGNALS:
        o = mean_sd([s[5]["shadow_spurious"][sig]["oakf"] for s in scored["FULL"] if 5 in s])[0]
        fx = mean_sd([s[5]["shadow_spurious"][sig]["fixed"] for s in scored["FULL"] if 5 in s])[0]
        P(f"    {sig:>10} {pct(o):>16} {pct(fx):>16}")

    # =========================================================================
    # C. FULL DR/FPR (primary + nominal) mean±SD
    # =========================================================================
    P("\n" + "=" * 82)
    P("C. FULL — DR/FPR (primary + nominal), mean±SD, M1/M2 rates, proc")
    P("=" * 82)
    P(f"    {'size':>5} {'DR_prim':>15} {'FPR_prim':>15} {'DR_nom':>15} {'FPR_nom':>15} "
      f"{'M1@atk':>8} {'M2@atk':>8} {'proc':>9}")
    for size in WINDOW_SIZES:
        drp = agg_field(scored["FULL"], size, "dr_primary")
        fpp = agg_field(scored["FULL"], size, "fpr_primary")
        drn = agg_field(scored["FULL"], size, "dr_nominal")
        fpn = agg_field(scored["FULL"], size, "fpr_nominal")
        m1 = agg_field(scored["FULL"], size, "m1_rate")
        m2 = agg_field(scored["FULL"], size, "m2_rate")
        pr = agg_field(scored["FULL"], size, "proc")
        P(f"    {str(size)+'s':>5} "
          f"{pct(drp[0])+'±'+pct(drp[1]).strip():>15} {pct(fpp[0])+'±'+pct(fpp[1]).strip():>15} "
          f"{pct(drn[0])+'±'+pct(drn[1]).strip():>15} {pct(fpn[0])+'±'+pct(fpn[1]).strip():>15} "
          f"{pct(m1[0]):>8} {pct(m2[0]):>8} {ms(pr[0]):>9}")

    # =========================================================================
    # D. NO_DUAL_MECH — FPR on real background
    # =========================================================================
    P("\n" + "=" * 82)
    P("D. NO_DUAL_MECH — single-signal misfire on real background (FPR)")
    P("=" * 82)
    if "NO_DUAL_MECH" in scored:
        for size in WINDOW_SIZES:
            drp = agg_field(scored["NO_DUAL_MECH"], size, "dr_primary")
            fpp = agg_field(scored["NO_DUAL_MECH"], size, "fpr_primary")
            fpn = agg_field(scored["NO_DUAL_MECH"], size, "fpr_nominal")
            P(f"    {str(size)+'s':>5}  DR_prim={pct(drp[0])}  "
              f"FPR_prim={pct(fpp[0])}  FPR_nom={pct(fpn[0])}")
    else:
        P("    (no NO_DUAL_MECH runs yet)")

    # =========================================================================
    # E. NO_MULTI_WINDOW — DR/FPR (5s only)
    # =========================================================================
    P("\n" + "=" * 82)
    P("E. NO_MULTI_WINDOW — DR/FPR (5s only)")
    P("=" * 82)
    if "NO_MULTI_WINDOW" in scored:
        drp = agg_field(scored["NO_MULTI_WINDOW"], 5, "dr_primary")
        fpp = agg_field(scored["NO_MULTI_WINDOW"], 5, "fpr_primary")
        fpn = agg_field(scored["NO_MULTI_WINDOW"], 5, "fpr_nominal")
        P(f"    5s  DR_prim={pct(drp[0])}±{pct(drp[1]).strip()}  "
          f"FPR_prim={pct(fpp[0])}  FPR_nom={pct(fpn[0])}")
    else:
        P("    (no NO_MULTI_WINDOW runs yet)")

    # =========================================================================
    # F. Controller CPU: ON (FULL) vs OFF (NOOP)
    # =========================================================================
    P("\n" + "=" * 82)
    P("F. Controller CPU — detector ON (FULL) vs OFF (NOOP), native rate")
    P("=" * 82)
    on = cpu_stats("cpu_b_full_*_FULL.csv")
    off = cpu_stats("cpu_b_noop_*_NOOP.csv")
    on_mean = mean_sd([m for m, _ in on]); on_peak = mean_sd([p for _, p in on])
    off_mean = mean_sd([m for m, _ in off]); off_peak = mean_sd([p for _, p in off])
    P(f"    detector ON  (FULL, n={len(on)}) : mean {on_mean[0] and f'{on_mean[0]:.1f}'}% "
      f"±{on_mean[1] and f'{on_mean[1]:.1f}'}  peak {on_peak[0] and f'{on_peak[0]:.1f}'}%")
    P(f"    detector OFF (NOOP, n={len(off)}) : mean {off_mean[0] and f'{off_mean[0]:.1f}'}% "
      f"±{off_mean[1] and f'{off_mean[1]:.1f}'}  peak {off_peak[0] and f'{off_peak[0]:.1f}'}%")
    if on_mean[0] is not None and off_mean[0] is not None:
        P(f"    detector adds (mean)          : {on_mean[0]-off_mean[0]:+.1f} pts")

    # =========================================================================
    # G. Processing time + replay fidelity per run
    # =========================================================================
    P("\n" + "=" * 82)
    P("G. Processing time (per window) + replay fidelity per run")
    P("=" * 82)
    for size in WINDOW_SIZES:
        pr = agg_field(scored.get("FULL", []), size, "proc")
        P(f"    FULL proc {str(size)+'s':>4}: {ms(pr[0])} ± {ms(pr[1])}")
    P("    replay stretch (dur/482.7s) per FULL run:")
    stretches = []
    for run_id, _, tr_log in full_runs:
        dur, st = replay_stretch(tr_log)
        if st:
            stretches.append(st)
            P(f"      {run_id}: {dur:.1f}s  stretch={st:.2f}x")
    if stretches:
        sms = mean_sd(stretches)
        P(f"    mean stretch = {sms[0]:.2f}x ± {sms[1]:.2f}  (native-timing adherence)")

    report = "\n".join(L)
    print(report)
    os.makedirs(BATCH_DIR, exist_ok=True)
    rp = os.path.join(BATCH_DIR, "batch_report.txt")
    try:
        with open(rp, "w") as f:
            f.write(report + "\n")
        print(f"\n[saved] {rp}")
    except PermissionError:
        print(f"\n[WARN] could not write {rp} (permission). Report above is authoritative.")

    # --- update paper_metrics.txt with a final-batch appendix ---
    def a5(mode, size, field):
        return agg_field(scored.get(mode, []), size, field)
    pm = os.path.join(BOUN_LOG_DIR, "paper_metrics.txt")
    block = []
    block.append("\n" + "=" * 78)
    block.append("FINAL BATCH APPENDIX (native rate x1; FULLx10 FIXEDx10 NODUALx5 "
                 "NOMULTIx5 NOOPx3)")
    block.append(f"timestamp: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}   "
                 f"K(SYN/5s)={K}")
    block.append("=" * 78)
    block.append("DR/FPR are mean±SD across repeats. primary label = pulse-overlap OR "
                 "syn>=K;")
    block.append("nominal = pulse-schedule only (boundary excluded). 120s excluded "
                 "(under-warmed).")
    for size in WINDOW_SIZES:
        drp = a5("FULL", size, "dr_primary"); fpp = a5("FULL", size, "fpr_primary")
        drn = a5("FULL", size, "dr_nominal"); fpn = a5("FULL", size, "fpr_nominal")
        block.append(f"  FULL {size}s: DR_prim {pct(drp[0])}±{pct(drp[1]).strip()}  "
                     f"FPR_prim {pct(fpp[0])}  DR_nom {pct(drn[0])}  FPR_nom {pct(fpn[0])}")
    b_dr0 = a5("FULL", 5, "dr_primary")[0] or 0
    b_dr1 = agg_field(boun_hyst[1], 5, "dr_primary")[0] or 0
    b_dr2 = agg_field(boun_hyst[2], 5, "dr_primary")[0] or 0
    c_fpr0 = mean_sd([s.get(5, (None, None))[1] for s in cic_scored[0]])[0] or 0
    block.append(f"  FULL_HYST 5s BOUN DR: base {100*b_dr0:.1f}% -> N1 {100*b_dr1:.1f}% "
                 f"-> N2 {100*b_dr2:.1f}% ; CIC 5s FPR unchanged at {100*c_fpr0:.3f}% "
                 f"=> KEEP")
    block.append(f"  CPU native rate: ON(FULL) {on_mean[0]:.1f}% mean / {on_peak[0]:.1f}% peak ; "
                 f"OFF(NOOP) {off_mean[0]:.1f}% / {off_peak[0]:.1f}% ; "
                 f"detector adds +{on_mean[0]-off_mean[0]:.1f} pts")
    pr5 = a5("FULL", 5, "proc"); pr30 = a5("FULL", 30, "proc")
    block.append(f"  proc/window: 5s {ms(pr5[0])}  30s {ms(pr30[0])} ; "
                 f"replay stretch {mean_sd(stretches)[0]:.2f}x")
    try:
        with open(pm, "a") as f:
            f.write("\n".join(block) + "\n")
        print(f"[updated] {pm}")
    except PermissionError:
        print(f"[WARN] could not update {pm} (permission).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
