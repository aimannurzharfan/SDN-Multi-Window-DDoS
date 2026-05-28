#!/usr/bin/env python3
"""
compute_metrics.py  —  Aggregate experimental results for Chapter 4.

Reads all per-run CSVs produced by multi_window_detector_v2.py,
labels cycles by phase, and computes:

  Per window (5s, 30s, 120s) per ablation mode:
    DR   = detected_attack_cycles / total_attack_cycles      (mean ± SD over 30 runs)
    FPR  = false_alert_calib_cycles / total_calib_cycles     (mean ± SD over 30 runs)
    proc = per-cycle processing time (ms)                    (mean ± SD over all cycles)

Output:
  - Console summary table (copy-paste into Chapter 4)
  - CSV: logs/metrics_summary.csv
  - CSV: logs/per_run_metrics.csv   (one row per run, for scatter plots)

Usage:
  python3 compute_metrics.py [logs_dir]

  logs_dir: path containing run_*.csv files (default: ~/sdn-thesis/logs)
"""

import csv
import glob
import os
import re
import statistics
import sys
from collections import defaultdict


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOGS_DIR = os.path.expanduser(sys.argv[1]) if len(sys.argv) > 1 else \
           os.path.expanduser("~/sdn-thesis/logs")

# Pattern: run_<RUN_ID>_chunk_<CHUNK_ID>_<MODE>.csv
CSV_PATTERN = os.path.join(LOGS_DIR, "run_*.csv")

WINDOWS  = ["5s", "30s", "120s"]
MODES    = ["FULL", "NO_MULTI_WINDOW", "NO_DUAL_MECH", "FIXED_THRESHOLD"]

# A cycle is labelled "attack" if its phase column == "attack".
# A cycle is labelled "calibration" if phase == "calibration".
# "post" cycles are excluded from both DR and FPR.


# ---------------------------------------------------------------------------
# Per-run data structure
# ---------------------------------------------------------------------------

class RunResult:
    """Holds raw cycle data for one CSV file (one run, one mode)."""
    def __init__(self, run_id, chunk_id, mode):
        self.run_id   = run_id
        self.chunk_id = chunk_id
        self.mode     = mode
        # window_name -> list of dicts (one per cycle row)
        self.cycles: dict = defaultdict(list)

    def add_cycle(self, window: str, row: dict):
        self.cycles[window].append(row)

    def dr(self, window: str) -> float | None:
        """Detection rate for a given window."""
        rows = self.cycles.get(window, [])
        attack_rows = [r for r in rows if r["phase"] == "attack"]
        if not attack_rows:
            return None
        return sum(int(r["alert"]) for r in attack_rows) / len(attack_rows)

    def fpr(self, window: str) -> float | None:
        """False positive rate for a given window."""
        rows = self.cycles.get(window, [])
        calib_rows = [r for r in rows if r["phase"] == "calibration"]
        if not calib_rows:
            return None
        return sum(int(r["alert"]) for r in calib_rows) / len(calib_rows)

    def proc_time_ms(self, window: str) -> float | None:
        rows = self.cycles.get(window, [])
        if not rows:
            return None
        return statistics.mean(float(r["proc_time_ms"]) for r in rows)


# ---------------------------------------------------------------------------
# Load all CSVs
# ---------------------------------------------------------------------------

def load_runs() -> list:
    files = sorted(glob.glob(CSV_PATTERN))
    if not files:
        print(f"[ERROR] No CSV files found at: {CSV_PATTERN}")
        print("        Run experiments first with batch_run.sh")
        sys.exit(1)

    runs = []
    for fpath in files:
        fname = os.path.basename(fpath)
        # Parse run_ID_chunk_CID_MODE.csv
        m = re.match(r"run_(.+)_chunk_(\d+)_([A-Z_]+)\.csv$", fname)
        if not m:
            print(f"[WARN] Skipping unrecognised file: {fname}")
            continue
        run_id, chunk_id, mode = m.group(1), m.group(2), m.group(3)
        run = RunResult(run_id, chunk_id, mode)

        with open(fpath, newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                window = row.get("window", "").strip()
                if window:
                    run.add_cycle(window, row)

        runs.append(run)

    print(f"Loaded {len(runs)} run CSVs from {LOGS_DIR}")
    return runs


# ---------------------------------------------------------------------------
# Aggregate per mode
# ---------------------------------------------------------------------------

def aggregate(runs: list) -> dict:
    """
    Returns nested dict:
      result[mode][window] = {
          "dr_values":   [float, ...],   # one per run
          "fpr_values":  [float, ...],
          "proc_values": [float, ...],
          "n_runs":      int,
      }
    """
    result = {
        mode: {win: {"dr_values": [], "fpr_values": [], "proc_values": []}
               for win in WINDOWS}
        for mode in MODES
    }

    for run in runs:
        mode = run.mode
        if mode not in result:
            continue
        for win in WINDOWS:
            dr  = run.dr(win)
            fpr = run.fpr(win)
            pt  = run.proc_time_ms(win)
            if dr  is not None: result[mode][win]["dr_values"].append(dr)
            if fpr is not None: result[mode][win]["fpr_values"].append(fpr)
            if pt  is not None: result[mode][win]["proc_values"].append(pt)

    return result


# ---------------------------------------------------------------------------
# Summary stats
# ---------------------------------------------------------------------------

def stats(values: list) -> tuple:
    """Returns (mean, sd, n) or (None, None, 0) if empty."""
    n = len(values)
    if n == 0:
        return None, None, 0
    mean = statistics.mean(values)
    sd   = statistics.stdev(values) if n > 1 else 0.0
    return mean, sd, n


def fmt(mean, sd) -> str:
    if mean is None:
        return "   n/a    "
    return f"{mean*100:6.2f}% ± {sd*100:.2f}%"


def fmt_ms(mean, sd) -> str:
    if mean is None:
        return "  n/a "
    return f"{mean:.3f} ± {sd:.3f} ms"


# ---------------------------------------------------------------------------
# Print table
# ---------------------------------------------------------------------------

def print_table(agg: dict):
    print()
    print("=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)

    header = f"{'Mode':<22} {'Window':<8} {'n':>3}  {'DR':>18}  {'FPR':>18}  {'ProcTime':>20}"
    print(header)
    print("-" * 80)

    for mode in MODES:
        wins = WINDOWS if mode != "NO_MULTI_WINDOW" else ["5s"]
        for win in wins:
            d = agg[mode][win]
            dr_m, dr_sd, n_dr   = stats(d["dr_values"])
            fpr_m, fpr_sd, n_fpr = stats(d["fpr_values"])
            pt_m, pt_sd, _       = stats(d["proc_values"])
            print(
                f"{mode:<22} {win:<8} {n_dr:>3}  "
                f"{fmt(dr_m, dr_sd):>18}  "
                f"{fmt(fpr_m, fpr_sd):>18}  "
                f"{fmt_ms(pt_m, pt_sd):>20}"
            )
        print()

    print("=" * 80)
    print()


# ---------------------------------------------------------------------------
# Benchmark comparison (from Chapter 2 — closed domain citations only)
# ---------------------------------------------------------------------------

def print_benchmark_comparison(agg: dict):
    print("BENCHMARK COMPARISON (FULL mode, 5 s window vs. primary benchmarks)")
    print("-" * 60)

    d = agg["FULL"]["5s"]
    dr_m, dr_sd, _ = stats(d["dr_values"])
    fpr_m, fpr_sd, _ = stats(d["fpr_values"])
    pt_m, pt_sd, _  = stats(d["proc_values"])

    if dr_m is not None:
        target_dr = 95.0
        print(f"  DR   (ours): {dr_m*100:.2f}% ± {dr_sd*100:.2f}%  "
              f"| target ≥ {target_dr:.1f}%  "
              f"| {'PASS' if dr_m*100 >= target_dr else 'FAIL'}")
        print(f"  DR   (Alashhab2024): 99.2%")

    if fpr_m is not None:
        target_fpr = 0.97
        print(f"  FPR  (ours): {fpr_m*100:.4f}% ± {fpr_sd*100:.4f}%  "
              f"| target < {target_fpr:.2f}%  "
              f"| {'PASS' if fpr_m*100 < target_fpr else 'FAIL'}")
        print(f"  FPR  (Aladaileh2022): 0.97%")

    if pt_m is not None:
        target_proc = 5000.0   # 5 s = 5000 ms per cycle (conservative)
        print(f"  Proc (ours): {pt_m:.3f} ± {pt_sd:.3f} ms  "
              f"| target < {target_proc:.0f} ms  "
              f"| {'PASS' if pt_m < target_proc else 'FAIL'}")
        print(f"  Proc (Ahmad2024 OAKF ref): 0.008 ms/cycle")

    print()


# ---------------------------------------------------------------------------
# Save CSV outputs
# ---------------------------------------------------------------------------

def save_csv(agg: dict, runs: list):
    summary_path = os.path.join(LOGS_DIR, "metrics_summary.csv")
    per_run_path = os.path.join(LOGS_DIR, "per_run_metrics.csv")

    # Summary CSV
    with open(summary_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mode", "window", "n_runs",
                    "dr_mean", "dr_sd",
                    "fpr_mean", "fpr_sd",
                    "proc_mean_ms", "proc_sd_ms"])
        for mode in MODES:
            wins = WINDOWS if mode != "NO_MULTI_WINDOW" else ["5s"]
            for win in wins:
                d = agg[mode][win]
                dr_m, dr_sd, n   = stats(d["dr_values"])
                fpr_m, fpr_sd, _ = stats(d["fpr_values"])
                pt_m, pt_sd, _   = stats(d["proc_values"])
                w.writerow([
                    mode, win, n,
                    f"{dr_m:.6f}"  if dr_m  is not None else "",
                    f"{dr_sd:.6f}" if dr_sd is not None else "",
                    f"{fpr_m:.6f}"  if fpr_m  is not None else "",
                    f"{fpr_sd:.6f}" if fpr_sd is not None else "",
                    f"{pt_m:.4f}"  if pt_m  is not None else "",
                    f"{pt_sd:.4f}" if pt_sd is not None else "",
                ])
    print(f"Summary CSV: {summary_path}")

    # Per-run CSV
    with open(per_run_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "chunk_id", "mode", "window",
                    "dr", "fpr", "proc_mean_ms",
                    "attack_cycles", "calib_cycles"])
        for run in sorted(runs, key=lambda r: (r.mode, r.chunk_id)):
            wins = WINDOWS if run.mode != "NO_MULTI_WINDOW" else ["5s"]
            for win in wins:
                rows = run.cycles.get(win, [])
                attack_cycles = sum(1 for r in rows if r["phase"] == "attack")
                calib_cycles  = sum(1 for r in rows if r["phase"] == "calibration")
                w.writerow([
                    run.run_id, run.chunk_id, run.mode, win,
                    f"{run.dr(win):.6f}"  if run.dr(win)  is not None else "",
                    f"{run.fpr(win):.6f}" if run.fpr(win) is not None else "",
                    f"{run.proc_time_ms(win):.4f}" if run.proc_time_ms(win) is not None else "",
                    attack_cycles, calib_cycles,
                ])
    print(f"Per-run CSV: {per_run_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    runs = load_runs()
    agg  = aggregate(runs)
    print_table(agg)
    print_benchmark_comparison(agg)
    save_csv(agg, runs)
    print("Done.")
