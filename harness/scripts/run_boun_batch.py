#!/usr/bin/env python3
"""
run_boun_batch.py — final BOUN live batch driver (native timing, multiplier 1).

Runs the pre-registered repeat plan by invoking experiment_boun.py once per
(mode, repeat) as an isolated subprocess, so a leak or hang in one run cannot
corrupt the next. Nothing about the experiment is changed here: same forwarding
offload, DRIFT_EXPERIMENT=1, native rate, unmodified detector, fixed OAKF/k/Q/R/
warmup/windows/signals. This driver only sequences runs and preserves per-run
artifacts for the post-hoc analyzer (analyze_boun_batch.py).

Plan (task-specified):
    FULL x10, FIXED_THRESHOLD x10, NO_DUAL_MECH x5, NO_MULTI_WINDOW x5,
    NOOP x3 (detector-OFF CPU baseline).

Per run it preserves (all under logs/boun/, batch artifacts under logs/boun/batch/):
    run_<run_id>_chunk_0_<MODE>.csv     detector CSV        (written by detector)
    cpu_<run_id>_<MODE>.csv             1 Hz CPU samples    (written by experiment_boun)
    batch/tcpreplay_<run_id>.log        tcpreplay --stats   (copied each run)
    batch/stdout_<run_id>.log           full run stdout
    batch/manifest.csv                  one row per run (status, replay dur, exit)

Usage:  sudo python3 harness/scripts/run_boun_batch.py
"""

import csv
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BOUN_LOG_DIR = os.path.join(REPO, "logs", "boun")
BATCH_DIR = os.path.join(BOUN_LOG_DIR, "batch")
EXPERIMENT = os.path.join(HERE, "experiment_boun.py")
TCPREPLAY_LOG = os.path.join(BOUN_LOG_DIR, "tcpreplay_boun.log")
MANIFEST = os.path.join(BATCH_DIR, "manifest.csv")

# Per-run wall budget: setup ~31s + replay (~570-720s under lag) + drain + scoring.
# 1500s (25 min) is a generous ceiling; a run exceeding it is treated as hung.
RUN_TIMEOUT_S = 1500

# NOOP first: it is the only new code path in this batch, so running it first
# means a defect surfaces at the first progress check (~12 min) rather than after
# hours. Run order is scientifically irrelevant (each run is fully isolated).
RUN_PLAN = [
    ("NOOP", 3, "noop"),
    ("FULL", 10, "full"),
    ("FIXED_THRESHOLD", 10, "fixed"),
    ("NO_DUAL_MECH", 5, "nodual"),
    ("NO_MULTI_WINDOW", 5, "nomulti"),
]


def ts():
    return time.strftime("%H:%M:%S")


def log(msg):
    print(f"[BATCH {ts()}] {msg}", flush=True)


def hard_clean():
    """Kill any stray Ryu/tcpreplay and clear Mininet state between runs."""
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "tcpreplay"], capture_output=True)
    subprocess.run(["mn", "--clean"], capture_output=True)
    time.sleep(3)


def manifest_append(row):
    new = not os.path.isfile(MANIFEST)
    with open(MANIFEST, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["run_id", "mode", "idx", "status", "exit_code",
                        "replay_dur_s", "wall_s", "finished_at"])
        w.writerow(row)


def parse_replay_dur(stdout_path):
    """Best-effort pull of the replay duration from a saved run stdout."""
    try:
        with open(stdout_path, errors="replace") as f:
            for line in f:
                if "REPLAY DONE in" in line:
                    # "... REPLAY DONE in 568.9 s ..."
                    import re
                    m = re.search(r"REPLAY DONE in ([\d.]+)", line)
                    if m:
                        return float(m.group(1))
    except OSError:
        pass
    return None


def run_one(mode, idx, short):
    run_id = f"b_{short}_{idx:02d}"
    stdout_path = os.path.join(BATCH_DIR, f"stdout_{run_id}.log")
    log(f"START {run_id} (mode={mode}, {idx}) -> {stdout_path}")
    hard_clean()

    t0 = time.time()
    status, exit_code = "ok", None
    with open(stdout_path, "w") as out:
        try:
            p = subprocess.run(
                [sys.executable, EXPERIMENT, mode, run_id],
                stdout=out, stderr=subprocess.STDOUT,
                timeout=RUN_TIMEOUT_S, cwd=REPO,
            )
            exit_code = p.returncode
            if exit_code != 0:
                status = "nonzero_exit"
        except subprocess.TimeoutExpired:
            status = "timeout"
            log(f"  !! {run_id} exceeded {RUN_TIMEOUT_S}s — killing and continuing")
    wall = time.time() - t0

    # Preserve this run's tcpreplay stats log (fixed name -> per-run copy).
    if os.path.isfile(TCPREPLAY_LOG):
        shutil.copy2(TCPREPLAY_LOG, os.path.join(BATCH_DIR, f"tcpreplay_{run_id}.log"))
    else:
        status = status if status != "ok" else "no_tcpreplay_log"

    # Verify the detector CSV exists (except NOOP, which writes none).
    if mode != "NOOP":
        csv_path = os.path.join(BOUN_LOG_DIR, f"run_{run_id}_chunk_0_{mode}.csv")
        if not os.path.isfile(csv_path):
            status = "no_detector_csv"

    replay_dur = parse_replay_dur(stdout_path)
    manifest_append([run_id, mode, idx, status, exit_code,
                     f"{replay_dur:.1f}" if replay_dur else "",
                     f"{wall:.1f}", time.strftime("%Y-%m-%d %H:%M:%S")])
    log(f"DONE  {run_id} status={status} exit={exit_code} "
        f"replay={replay_dur}s wall={wall:.0f}s")
    return status


def main():
    if os.geteuid() != 0:
        print("Must run as root: sudo python3 harness/scripts/run_boun_batch.py")
        return 1
    os.makedirs(BATCH_DIR, exist_ok=True)

    total = sum(n for _, n, _ in RUN_PLAN)
    log(f"=== BOUN FINAL BATCH: {total} runs "
        f"({', '.join(f'{m}x{n}' for m, n, _ in RUN_PLAN)}) ===")
    log(f"per-run timeout={RUN_TIMEOUT_S}s; artifacts -> {BATCH_DIR}")

    done = 0
    counts = {}
    for mode, n, short in RUN_PLAN:
        for i in range(1, n + 1):
            st = run_one(mode, i, short)
            done += 1
            counts[st] = counts.get(st, 0) + 1
            log(f"progress {done}/{total}  (status tally: {counts})")

    hard_clean()
    log(f"=== BATCH COMPLETE: {done}/{total} runs; status tally {counts} ===")
    log(f"manifest: {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
