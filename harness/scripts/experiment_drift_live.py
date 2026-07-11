#!/usr/bin/env python3
"""
experiment_drift_live.py — ONE live drift trial through Mininet+Ryu.

Reuses the BOUN machinery (experiment_boun): Ryu + unmodified
multi_window_detector_v2 (DRIFT_EXPERIMENT=1), tree_5sw_20h, and
install_forwarding_offload() (established/RST-ACK background kept off the
controller). OAKF params unchanged. Native timing.

Live drift: drift_live_gen.py runs a non-stationary legit baseline on h1 (active
source-IP set 20->400), and injects a MODERATE spoofed-SYN burst (M fixed sources)
on h16 at EARLY / MID / LATE points along the drift. The detector logs per-5s-window
entropy / revisit / synack + OAKF anomaly flags; Ryu CPU is sampled at 1 Hz.

Writes: logs/boun/drift_live/run_<run_id>_chunk_0_FULL.csv (detector),
        logs/boun/drift_live/schedule_<run_id>.json (t0, attack intervals, params),
        logs/boun/drift_live/cpu_<run_id>.csv.

Usage: sudo python3 harness/scripts/experiment_drift_live.py [run_id]
"""
import json, os, sys, threading, time, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import experiment as exp
import experiment_boun as eb

REPO = exp.THESIS_DIR
GEN = os.path.join(REPO, "harness", "traffic", "drift_live_gen.py")
DRIFT_LIVE_DIR = os.path.join(REPO, "logs", "boun", "drift_live")
eb.BOUN_LOG_DIR = DRIFT_LIVE_DIR          # redirect detector CSV + ryu log here

# ---- trial parameters ----
DUR         = float(os.environ.get("DRIFT_DUR", 480))
N_LOW, N_HIGH = 20, 200                     # entropy ~4.3 -> ~7.6 bits
DRIFT_START, DRIFT_END = 80.0, 460.0
LEGIT_PPS   = 120                           # enough to cover N_HIGH uniquely per window
DST         = "10.0.0.2"                   # closed port on h2 -> RST (RST+ACK offloaded)
# "Same attack intensity" = same entropy-SIGNATURE magnitude (as offline): the
# spoofed-source count is SCALED to the current baseline so the attack raises
# entropy by ~ATK_D bits at every injection point (a fixed source-count would
# shrink to a vanishing signature on the log-compressed high baseline -> nothing,
# OAKF or fixed, could detect it). M(t) = round(N(t) * (2^ATK_D - 1)).
ATK_D       = 2.5                           # target entropy deviation (bits)
ATK_PPS     = 300                           # cover the (larger, late) spoofed set
ATK_DUR     = 15
ATK_OFFSETS = (110.0, 270.0, 420.0)        # early / mid / late (gen elapsed)


def _n_at(gee):
    if gee <= DRIFT_START:
        return N_LOW
    if gee >= DRIFT_END:
        return N_HIGH
    return N_LOW + (N_HIGH - N_LOW) * (gee - DRIFT_START) / (DRIFT_END - DRIFT_START)


def _atk_m(gee):
    return max(20, int(round(_n_at(gee) * (2 ** ATK_D - 1))))


def main():
    if os.geteuid() != 0:
        exp.die("Must run as root: sudo python3 experiment_drift_live.py [run_id]")
    run_id = sys.argv[1] if len(sys.argv) > 1 else "drift_live"
    os.makedirs(DRIFT_LIVE_DIR, exist_ok=True)
    calib_secs = exp.RYU_STARTUP_SECS + exp.TOPO_SETTLE_SECS + 6 + DRIFT_START

    exp.log(f"=== LIVE DRIFT | run_id={run_id} dur={DUR:.0f}s attacks@{ATK_OFFSETS} ===")
    ryu_proc = None
    net = None
    cpu = []
    stop = threading.Event()

    def cleanup():
        stop.set()
        try:
            if net is not None:
                net.get("h1").cmd("pkill -f drift_live_gen 2>/dev/null")
                net.stop()
        except Exception:
            pass
        if ryu_proc and ryu_proc.poll() is None:
            ryu_proc.terminate()
            try:
                ryu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                ryu_proc.kill()
        subprocess.run(["mn", "--clean"], capture_output=True)

    try:
        exp.preflight_cleanup()
        ryu_proc = eb.start_ryu_boun("FULL", run_id, calib_secs)
        net = eb.start_mininet_boun()
        eb.install_forwarding_offload()

        sampler = threading.Thread(target=eb.sample_cpu, args=(ryu_proc.pid, stop, cpu), daemon=True)
        sampler.start()

        h1 = net.get("h1")
        h16 = net.get("h16")
        gen_log = os.path.join(DRIFT_LIVE_DIR, f"gen_{run_id}.log")
        exp.log(f"Starting live legit drift on h1 (N {N_LOW}->{N_HIGH}, {LEGIT_PPS}pps, {DUR:.0f}s)")
        h1.cmd(f"python3 {GEN} legit {DUR:.0f} {N_LOW} {N_HIGH} {DRIFT_START:.0f} "
               f"{DRIFT_END:.0f} {LEGIT_PPS} {DST} > {gen_log} 2>&1 &")
        t0 = time.time()

        intervals = []
        for k, off in enumerate(ATK_OFFSETS):
            tgt = t0 + off
            while time.time() < tgt and not stop.is_set():
                time.sleep(0.5)
            a0 = time.time()
            m_k = _atk_m(a0 - t0)          # scale spoofed set to current baseline
            exp.log(f"ATTACK {k} (offset {off:.0f}s, gen_elapsed {a0-t0:.0f}s): "
                    f"M={m_k} spoofed SYN {ATK_DUR}s (target +{ATK_D} bits)")
            h16.cmd(f"python3 {GEN} attack {ATK_DUR} {m_k} {ATK_PPS} {DST} "
                    f">> {gen_log} 2>&1")
            a1 = time.time()
            intervals.append({"group": ["early", "mid", "late"][k],
                              "start": a0 - t0, "end": a1 - t0,
                              "wall_start": a0, "wall_end": a1, "m": m_k})

        # drain to full duration
        while time.time() - t0 < DUR and not stop.is_set():
            time.sleep(1.0)
        time.sleep(eb.POST_REPLAY_SECS)

        stop.set()
        sampler.join(timeout=5)
        h1.cmd("pkill -f drift_live_gen 2>/dev/null")

        if ryu_proc.poll() is None:
            ryu_proc.terminate()
            try:
                ryu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                ryu_proc.kill()
        net.stop(); net = None
        subprocess.run(["mn", "--clean"], capture_output=True)

        # persist schedule + cpu
        sched = {"run_id": run_id, "t0": t0, "dur": DUR,
                 "n_low": N_LOW, "n_high": N_HIGH,
                 "drift_start": DRIFT_START, "drift_end": DRIFT_END,
                 "legit_pps": LEGIT_PPS, "atk_d": ATK_D, "atk_pps": ATK_PPS,
                 "atk_dur": ATK_DUR, "attacks": intervals}
        with open(os.path.join(DRIFT_LIVE_DIR, f"schedule_{run_id}.json"), "w") as f:
            json.dump(sched, f, indent=2)
        import csv as _csv
        with open(os.path.join(DRIFT_LIVE_DIR, f"cpu_{run_id}.csv"), "w", newline="") as f:
            w = _csv.writer(f); w.writerow(["elapsed_s", "ryu_cpu_pct", "system_cpu_pct"])
            w.writerows(cpu)

        csv_path = os.path.join(DRIFT_LIVE_DIR, f"run_{run_id}_chunk_0_FULL.csv")
        cpu_mean = (sum(c[1] for c in cpu) / len(cpu)) if cpu else 0
        cpu_peak = max((c[1] for c in cpu), default=0)
        exp.log(f"=== DONE {run_id}: CSV={os.path.basename(csv_path)} exists={os.path.isfile(csv_path)} "
                f"attacks={len(intervals)} Ryu CPU mean/peak={cpu_mean:.0f}/{cpu_peak:.0f}% ===")
    except Exception as e:
        exp.log(f"[EXCEPTION] {e}")
        cleanup()
        raise


if __name__ == "__main__":
    main()
