#!/usr/bin/env python3
"""
experiment_boun.py — BOUN live-replay harness (cross-dataset validation).

Adapts experiment.py to replay the real Boğaziçi (BOUN) TCP DDoS capture LIVE
through the same Mininet + Ryu + multi_window_detector_v2 stack used for the
CIC-DDoS2019 study, so the offline eval_boun.py result can be reproduced on-line.

What differs from experiment.py
-------------------------------
1. Traffic source. There is no separate calibration/attack phase and no
   synthetic legit generator. The WHOLE boun_tcp.pcap (built by
   build_boun_pcap.py) is replayed once, at NATIVE timing (tcpreplay default
   multiplier 1, pcap timestamps preserved). BOUN's own clean 0-80 s prefix is
   the calibration span; the four documented pulses live inside the same file.

2. Real SYN-ACKs are KEPT. The CIC harness installs a dataplane SYN-ACK DROP
   rule at calibration end (that is the only reason M2 fired there). BOUN is real
   bidirectional traffic with genuine SYN-ACKs — dropping them would defeat the
   whole point of the cross-dataset check. We therefore run the detector with
   DRIFT_EXPERIMENT=1, whose sole effects are (a) it suppresses that DROP rule
   and (b) it relabels post-calibration cycles "drift". Label (b) is irrelevant
   here because scoring is done by a pulse-aware post-processor (below), not by
   the detector's phase column.

3. No per-host iptables and no packet_in drain. The BOUN destination IPs are not
   owned by any Mininet host, so h1-h15 never reply; there is nothing to
   suppress. The pcap already contains the real server SYN-ACKs.

4. CIC-style established-flow offload (control-plane relief). The shared detector
   (multi_window_detector_v2.py, UNMODIFIED) installs only a table-miss ->
   CONTROLLER rule, so EVERY frame becomes a packet_in. On the CIC chunk that is
   fine — the traffic reaching the controller IS the (single-/few-source) SYN
   flood. BOUN is different: its bulk is 5.86M bare ACKs belonging to ALREADY-
   ESTABLISHED background connections. Sending all of them to the controller
   buried the packet_in queue in the first smoke test (detector saw only 40.4 %
   of offered frames) and time-smeared the pure-SYN pulses M2 keys on, collapsing
   synack_ratio to ~1.4 (offline it is ~17). CIC's design intent is that
   established flows are handled in the dataplane and only NEW flows reach the
   controller; we realise that intent with ONE installed dataplane rule per
   switch (see install_forwarding_offload) that matches established-connection
   packets (ACK set, SYN clear -> bareACK / PSH-ACK / FIN-ACK / RST-ACK) and
   keeps them OFF the control plane. Pure SYN (SYN set, ACK clear = the spoofed
   flood) and SYN-ACK (SYN+ACK = real server replies, kept because
   DRIFT_EXPERIMENT=1) do NOT match, so they still fall through the table-miss to
   the controller and are counted. The match is on TCP flags, not a learned
   5-tuple, so EVERY pure-SYN flood packet still generates a packet_in — no flood
   packet is hidden by the offload.

Unchanged (identical to CIC)
----------------------------
* Ryu + multi_window_detector_v2.py, tree_5sw_20h topology.
* OAKF parameters (warmup_cycles=3, Q/R/k) — not touched.
* 5 s / 30 s / 120 s windows and all signal definitions.
* The 24-column CIC CSV schema (plus the additive shadow columns) — so
  compute_metrics.py reads it unchanged.
* 1 Hz Ryu-process CPU sampling (same psutil sampler as measure_cpu.py).

Scoring (pulse-aware post-processor, mirrors eval_boun.py)
----------------------------------------------------------
Each detector cycle is mapped back to BOUN-relative time using its wall-clock
timestamp minus the recorded replay-start instant. A cycle is:
  * calibration (warm-up, NOT scored) if its window ends at BOUN t <= 80.22 s;
  * attack       if its window overlaps a pulse by >= 50 % of the window;
  * boundary     (excluded) if it overlaps a pulse by < 50 %;
  * legitimate   otherwise.
DR = detected(alert) attack windows / attack windows; FPR = alert legit / legit.
The pulse table and labelling rule are copied verbatim from eval_boun.py.

Usage (must run as root — Mininet requires it):
    sudo python3 harness/scripts/experiment_boun.py [ABLATION_MODE] [run_id]
        ABLATION_MODE : FULL (default) | NO_MULTI_WINDOW | NO_DUAL_MECH | FIXED_THRESHOLD
        run_id        : CSV label (default "boun")
"""

import csv
import os
import statistics
import subprocess
import sys
import threading
import time

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import experiment as exp  # noqa: E402  (reuse RYU_MANAGER, DETECTOR_PY, log(), preflight)

REPO = exp.THESIS_DIR
PCAP_PATH = os.path.join(REPO, "datasets", "boun", "boun_tcp.pcap")
BOUN_LOG_DIR = os.path.join(REPO, "logs", "boun")

ATTACKER_HOST = "h16"
ATTACKER_IF = "h16-eth0"

# Post-replay drain: allow the last 120 s window cycle to fire and flush.
POST_REPLAY_SECS = int(os.environ.get("BOUN_POST_SECS", 8))

# ---------------------------------------------------------------------------
# Pulse table + labelling — COPIED VERBATIM from harness/analysis/eval_boun.py
# (Erhan & Anarim 2020, Data in Brief, Table 1). Source of truth.
# ---------------------------------------------------------------------------
ATTACK_TABLE = [
    # rate_pps, start_s,    end_s
    (1000,      80.22269,   102.20233),
    (1500,      180.17426,  203.08441),
    (2000,      279.97402,  301.79111),
    (2500,      380.10981,  402.35755),
]
FIRST_ATTACK_START = min(a[1] for a in ATTACK_TABLE)   # 80.22269
ATTACK_LABEL_OVERLAP = 0.5
WINDOW_SIZES = (5, 30, 120)


def label_window(start, end):
    """('attack', rate) | ('legit', None) | ('boundary', None) — from eval_boun."""
    size = end - start
    best_frac = 0.0
    best_rate = None
    any_overlap = False
    for rate, a0, a1 in ATTACK_TABLE:
        ov = max(0.0, min(end, a1) - max(start, a0))
        if ov > 0:
            any_overlap = True
        frac = ov / size if size > 0 else 0.0
        if frac > best_frac:
            best_frac = frac
            best_rate = rate
    if best_frac >= ATTACK_LABEL_OVERLAP:
        return "attack", best_rate
    if any_overlap:
        return "boundary", None
    return "legit", None


# ---------------------------------------------------------------------------
# Ryu (BOUN-specific env)
# ---------------------------------------------------------------------------

def start_ryu_boun(ablation_mode: str, run_id: str, calib_secs: float) -> subprocess.Popen:
    if not os.path.isfile(exp.RYU_MANAGER):
        exp.die(f"ryu-manager not found at {exp.RYU_MANAGER}")
    if not os.path.isfile(exp.DETECTOR_PY):
        exp.die(f"Detector not found: {exp.DETECTOR_PY}")

    env = os.environ.copy()
    env.update({
        "RUN_ID":           run_id,
        "CHUNK_ID":         "0",
        "ABLATION_MODE":    ablation_mode,
        "CALIBRATION_SECS": str(int(calib_secs)),
        "ATTACK_SECS":      "600",           # keep detector alive for whole replay
        "DRIFT_EXPERIMENT": "1",             # keep real SYN-ACKs (no dataplane DROP)
        "LOG_DIR":          BOUN_LOG_DIR,
        "PYTHONPATH":       exp.DETECTOR_DIR + ":" + env.get("PYTHONPATH", ""),
    })

    os.makedirs(BOUN_LOG_DIR, exist_ok=True)
    ryu_log = os.path.join(BOUN_LOG_DIR, f"ryu_{run_id}_{ablation_mode}.log")
    exp.log(f"Starting Ryu (DRIFT_EXPERIMENT=1, keep SYN-ACKs) -> {ryu_log}")
    ryu_proc = subprocess.Popen(
        [exp.RYU_MANAGER, "--verbose", "--log-file", ryu_log, exp.DETECTOR_PY],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    exp.log(f"Ryu PID={ryu_proc.pid}. Waiting {exp.RYU_STARTUP_SECS} s ...")
    time.sleep(exp.RYU_STARTUP_SECS)
    if ryu_proc.poll() is not None:
        exp.die(f"Ryu exited early (code {ryu_proc.returncode}). See {ryu_log}")
    return ryu_proc


# ---------------------------------------------------------------------------
# Mininet (lean: topology only — the pcap IS the traffic)
# ---------------------------------------------------------------------------

def start_mininet_boun():
    sys.path.insert(0, exp.TOPOLOGY_DIR)
    from tree_5sw_20h import build_topology  # noqa: PLC0415
    exp.log("Building Mininet topology ...")
    net = build_topology()
    net.start()
    exp.log(f"Topology started. Waiting {exp.TOPO_SETTLE_SECS} s for OF handshakes ...")
    time.sleep(exp.TOPO_SETTLE_SECS)
    return net


# ---------------------------------------------------------------------------
# CIC-style established-flow offload (control-plane relief)
# ---------------------------------------------------------------------------
# One installed dataplane rule per switch. It matches established-connection TCP
# (ACK set, SYN clear) and keeps it off the control plane, so only new-flow SYN
# and the real SYN-ACK replies reach the detector — restoring the SYN-dominated
# packet_in stream M2 needs. See the module docstring (point 4) for rationale.
#
# priority: the detector's table-miss is priority 0, so any positive priority
# wins for the matched (established) packets while SYN / SYN-ACK still fall
# through to the table-miss -> CONTROLLER.
#
# action=drop (not NORMAL): BOUN destination IPs are not owned by any Mininet
# host, so no host would ever reply and dataplane *delivery* is a no-op. From the
# detector's and the endpoints' point of view, dropping the bare-ACK background
# is identical to NORMAL-forwarding it (the detector never sees it either way),
# but drop avoids a broadcast-flood storm on the 100 Mbit leaf links (the pcap's
# L2 dst is broadcast) that would otherwise congest the dataplane and drop the
# very SYN pulses we need to observe.
OFFLOAD_PRIORITY = 50
OFFLOAD_SWITCHES = [f"s{i}" for i in range(1, 6)]


def install_forwarding_offload():
    """Install the established-flow (ACK & !SYN) offload rule on s1-s5.

    Mirrors experiment.py's ovs-ofctl flow-install pattern (same tool, same
    OpenFlow13 channel). Returns the number of switches the rule landed on.
    """
    exp.log(f"Installing CIC-style established-flow offload on "
            f"{','.join(OFFLOAD_SWITCHES)} "
            f"(tcp,+ack-syn -> drop, priority={OFFLOAD_PRIORITY}; "
            f"SYN / SYN-ACK stay on the control plane) ...")
    n = 0
    for sw in OFFLOAD_SWITCHES:
        ret = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", sw,
             f"priority={OFFLOAD_PRIORITY},tcp,tcp_flags=+ack-syn,actions=drop"],
            capture_output=True, text=True,
        )
        if ret.returncode != 0:
            exp.log(f"  [WARN] ovs-ofctl {sw}: {ret.stderr.strip()}")
        else:
            n += 1
    exp.log(f"Offload rule installed on {n}/{len(OFFLOAD_SWITCHES)} switch(es). "
            f"Established bare-ACK background now handled in the dataplane; "
            f"only SYN / SYN-ACK reach the detector.")
    return n


# ---------------------------------------------------------------------------
# CPU sampler (identical method to measure_cpu.sample_cpu)
# ---------------------------------------------------------------------------

def sample_cpu(pid: int, stop_event: threading.Event, out: list):
    proc = psutil.Process(pid)
    proc.cpu_percent(None)          # prime (first call returns 0.0)
    psutil.cpu_percent(None)
    t0 = time.time()
    while not stop_event.is_set():
        if stop_event.wait(1.0):
            break
        try:
            ryu_cpu = proc.cpu_percent(None)
        except psutil.NoSuchProcess:
            break
        sys_cpu = psutil.cpu_percent(None)
        out.append((round(time.time() - t0, 2), ryu_cpu, sys_cpu))


# ---------------------------------------------------------------------------
# Native-timing replay of the whole pcap
# ---------------------------------------------------------------------------

def replay_boun(net) -> tuple:
    """Replay the entire pcap at native timing on the attacker NIC.

    Returns (t_replay_start_wall, tcpreplay_log_path). tcpreplay's default
    multiplier is 1.0 (pcap timestamps honoured), so the four pulses land at
    their captured offsets. --preload-pcap loads the 426 MB file into RAM first
    so replay pacing is not disk-bound.
    """
    if not os.path.isfile(PCAP_PATH):
        exp.die(f"BOUN pcap not found: {PCAP_PATH}. Run build_boun_pcap.py first.")

    h16 = net.get(ATTACKER_HOST)
    tr_log = os.path.join(BOUN_LOG_DIR, "tcpreplay_boun.log")
    exp.log(f"REPLAY START: tcpreplay {os.path.basename(PCAP_PATH)} on {ATTACKER_IF} "
            f"at NATIVE timing (multiplier 1) ...")
    t_replay = time.time()
    h16.cmd(
        f"tcpreplay --intf1={ATTACKER_IF} --preload-pcap --stats=15 "
        f"{PCAP_PATH} > {tr_log} 2>&1"
    )
    dt = time.time() - t_replay
    exp.log(f"REPLAY DONE in {dt:.1f} s (pcap span ~482.7 s).")
    return t_replay, tr_log


def parse_tcpreplay_log(path: str) -> dict:
    """Pull actual pps / packet counts / behind-schedule from tcpreplay output."""
    info = {"raw": "", "actual_pps": None, "sent": None, "duration": None,
            "failed": None, "behind": None}
    if not os.path.isfile(path):
        return info
    with open(path, errors="replace") as f:
        txt = f.read()
    info["raw"] = txt
    for line in txt.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("actual:"):
            # "Actual: 6090873 packets (426.. bytes) sent in 482.66 seconds"
            info["actual_line"] = s
            import re
            m = re.search(r"Actual:\s*([\d,]+)\s*packets.*sent in ([\d.]+)", s)
            if m:
                info["sent"] = int(m.group(1).replace(",", ""))
                info["duration"] = float(m.group(2))
        if "rated:" in low:
            import re
            m = re.search(r"([\d.]+)\s*pps", s)
            if m:
                info["actual_pps"] = float(m.group(1))
        if "failed packets" in low:
            import re
            m = re.search(r"failed packets:\s*([\d,]+)", low)
            if m:
                info["failed"] = int(m.group(1).replace(",", ""))
    if info["sent"] and info["duration"]:
        info["derived_pps"] = info["sent"] / info["duration"]
        # tcpreplay "kept up" if it finished within a few % of the pcap span.
        info["behind"] = info["duration"] - 482.66
    return info


# ---------------------------------------------------------------------------
# Post-processor — pulse-aware DR / FPR (mirrors eval_boun.py)
# ---------------------------------------------------------------------------

def score(csv_path: str, tr_log: str) -> dict:
    """Score DR/FPR using the CORRECTED, stats-based wall->BOUN mapping.

    The live replay cannot hold native timing (the saturated controller
    back-pressures tcpreplay), so a naive `wall - t_replay` mapping mislabels
    pulses. recompute_boun_labels.analyze() reconstructs the true mapping from
    tcpreplay's own --stats curve (packets-sent -> BOUN time via pcap order).
    """
    import recompute_boun_labels as rc  # noqa: PLC0415  (same-dir helper)
    per = rc.analyze(csv_path, tr_log)

    out = {}
    for size in WINDOW_SIZES:
        recs = [{
            "boun_start": x["boun_start"], "boun_end": x["boun_end"],
            "phase": x["phase"], "label": x["label"], "rate": x["rate"],
            "entropy": x["entropy"], "revisit": x["revisit"],
            "synack_ratio": x["synack"], "packets": x["packets"],
            "unique_ips": x["uniq"], "syn": x["syn"], "synack": x["synA"],
            "M1": x["M1"], "M2": x["M2"], "alert": x["alert"],
            "proc_time_ms": x["proc"],
        } for x in per[size]]
        evals = [x for x in recs if x["phase"] == "eval"]
        calib = [x for x in recs if x["phase"] == "calibration"]
        attack = [x for x in evals if x["label"] == "attack"]
        legit = [x for x in evals if x["label"] == "legit"]
        boundary = [x for x in evals if x["label"] == "boundary"]
        proc = [x["proc_time_ms"] for x in recs]
        out[size] = {
            "recs": recs, "n_calib": len(calib), "n_eval": len(evals),
            "attack": attack, "legit": legit, "n_boundary": len(boundary),
            "dr": (sum(x["alert"] for x in attack), len(attack)),
            "fpr": (sum(x["alert"] for x in legit), len(legit)),
            "m1_on_attack": sum(x["M1"] for x in attack),
            "m2_on_attack": sum(x["M2"] for x in attack),
            "mean_proc_ms": statistics.mean(proc) if proc else 0.0,
        }
    return out


def fmt_pct(hits, total):
    return "   n/a" if total == 0 else f"{100.0 * hits / total:6.2f}%"


def sanity_dump(recs: list, size: int):
    """Print a spread of cycles: calibration + around each pulse."""
    cols = (f"  {'boun_t':>13} {'label':>7} {'rate':>5} "
            f"{'entropy':>8} {'revisit':>9} {'synack':>10} "
            f"{'syn':>7} {'synA':>6} {'M1':>3} {'M2':>3} {'AL':>3}")

    def emit(x):
        return (f"  {x['boun_start']:6.0f}-{x['boun_end']:<6.0f} "
                f"{x['label'][:7]:>7} {str(x['rate'] or '-'):>5} "
                f"{x['entropy']:8.3f} {x['revisit']:9.2f} {x['synack_ratio']:10.2f} "
                f"{x['syn']:7d} {x['synack']:6d} "
                f"{'Y' if x['M1'] else '.':>3} {'Y' if x['M2'] else '.':>3} "
                f"{'Y' if x['alert'] else '.':>3}")

    # A few calibration cycles, then any attack cycles, plus their neighbours.
    calib = [x for x in recs if x["phase"] == "calibration"]
    attack_idx = [i for i, x in enumerate(recs) if x["label"] == "attack"]
    picks = []
    # up to 4 calibration cycles
    step = max(1, len(calib) // 4)
    picks += calib[::step][:4]
    # each attack cycle plus one before / after for context
    seen = set(id(x) for x in picks)
    for i in attack_idx:
        for j in (i - 1, i, i + 1):
            if 0 <= j < len(recs) and id(recs[j]) not in seen:
                picks.append(recs[j])
                seen.add(id(recs[j]))
    print(cols)
    # keep chronological order
    for x in sorted(picks, key=lambda r: r["boun_start"]):
        print(emit(x))


def summarise_cpu(samples: list) -> dict:
    if not samples:
        return {"n": 0, "mean": 0.0, "peak": 0.0, "sys_mean": 0.0, "sys_peak": 0.0}
    ryu = [s[1] for s in samples]
    sysc = [s[2] for s in samples]
    return {"n": len(samples), "mean": statistics.mean(ryu), "peak": max(ryu),
            "sys_mean": statistics.mean(sysc), "sys_peak": max(sysc)}


def pulse_breakdown(recs, size):
    """Per-pulse (per-rate) summary for the attack windows of one window size.

    Returns a list of dicts (one per documented rate, in rate order) with the
    mean synack_ratio, M1/M2 fire counts, and mean per-window packet_in rate
    (packets / window_seconds) — the M2-recovery evidence.
    """
    from collections import defaultdict
    by_rate = defaultdict(list)
    for x in recs:
        if x["label"] == "attack" and x["rate"] is not None:
            by_rate[x["rate"]].append(x)
    out = []
    for rate in sorted(by_rate):
        xs = by_rate[rate]
        syn = sum(x["syn"] for x in xs)
        synack = sum(x["synack"] for x in xs)
        out.append({
            "rate": rate, "n": len(xs),
            "mean_synack_ratio": statistics.mean([x["synack_ratio"] for x in xs]),
            "syn_sum": syn, "synack_sum": synack,
            "pooled_ratio": (syn / synack) if synack else float("inf"),
            "m1": sum(x["M1"] for x in xs), "m2": sum(x["M2"] for x in xs),
            "alert": sum(x["alert"] for x in xs),
            "mean_pktin_rate": statistics.mean([x["packets"] / size for x in xs]),
        })
    return out


def packetin_rate_split(recs, size):
    """Mean per-window packet_in rate (pkts/s) for pulse vs gap (5s eval windows).

    'pulse' = attack-labelled eval windows; 'gap' = legit eval windows. Shows
    whether the bare-ACK background dropped off the control plane (gap rate low).
    """
    ev = [x for x in recs if x["phase"] == "eval"]
    pulse = [x["packets"] / size for x in ev if x["label"] == "attack"]
    gap = [x["packets"] / size for x in ev if x["label"] == "legit"]
    return {
        "pulse_mean": statistics.mean(pulse) if pulse else 0.0,
        "gap_mean": statistics.mean(gap) if gap else 0.0,
        "pulse_n": len(pulse), "gap_n": len(gap),
    }


def write_paper_metrics(path, tr_info, cpu, scored, ablation_mode):
    """Persist the paper-ready metrics block (items 1-6) to logs/boun/."""
    P, span = 6090873, 482.66
    dur = tr_info.get("duration")
    sent = tr_info.get("sent")
    L = []
    a = L.append
    a("=" * 78)
    a("BOUN LIVE-REPLAY — PAPER METRICS  (CIC-style forwarding offload applied)")
    a(f"timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}   mode={ablation_mode}")
    a("=" * 78)

    a("\n[1] BOUN CHARACTERISATION (confirmed from datasets/boun/boun_tcp.pcap)")
    a(f"    TCP frames (pcap)          : {P:,}   (capinfos: 6,090k)")
    a(f"    capture span               : {span:.1f} s   (capinfos: 482.662757 s)")
    a("    handshake classes (build-verified, whole capture):")
    a("        pureSYN 181,719 | SYN-ACK 39,369 | bareACK 5,858,488")
    a("    pulses (Erhan & Anarim 2020, Table 1) — start/end s @ rate:")
    for rate, a0, a1 in ATTACK_TABLE:
        a(f"        {a0:7.2f}-{a1:7.2f} s  @ {rate} pps")
    a("    in-attack (offline windows_5s, >=50% overlap attack windows):")
    a("        SYN:SYN-ACK ~16.7 ; ~133k spoofed sources (sum of per-5s unique src)")
    a("        offline synack_v1 during pulses: 8.66-34.56 (mean 17.62)")

    a("\n[2] DETECTION PER WINDOW (corrected stats-based wall->BOUN mapping)")
    a(f"    {'window':>7} {'attackW':>8} {'det':>5} {'DR':>9} "
      f"{'legitW':>7} {'FP':>4} {'FPR':>9} {'M1@atk':>7} {'M2@atk':>7}")
    for size in WINDOW_SIZES:
        s = scored[size]
        drh, drt = s["dr"]; fph, fpt = s["fpr"]
        a(f"    {str(size)+'s':>7} {drt:>8} {drh:>5} {fmt_pct(drh, drt):>9} "
          f"{fpt:>7} {fph:>4} {fmt_pct(fph, fpt):>9} "
          f"{s['m1_on_attack']:>7} {s['m2_on_attack']:>7}")

    a("\n[3] PROCESSING TIME (mean per window cycle)")
    for size in WINDOW_SIZES:
        a(f"    {str(size)+'s':>7} : {scored[size]['mean_proc_ms']:.3f} ms")

    a("\n[4] CONTROLLER CPU (Ryu process, detector ON)")
    a(f"    mean / peak : {cpu['mean']:.1f}% / {cpu['peak']:.1f}%  "
      f"(system {cpu['sys_mean']:.1f}% / {cpu['sys_peak']:.1f}%)")
    a("    NOTE: detector-OFF no-op baseline at native rate still required for the")
    a("    A/B (Table 4.2 analog) — run in the batch, not in this single smoke test.")

    a("\n[5] REPLAY FIDELITY (systems observation)")
    if sent is not None and dur:
        behind = dur - span
        a(f"    tcpreplay sent {sent:,} pkts in {dur:.1f} s (pcap span {span:.1f} s)")
        a(f"    achieved avg rate {sent / dur:,.0f} pps ; "
          f"{'KEPT native timing' if behind <= span*0.05 else f'BEHIND by {behind:+.1f} s'}")
    if tr_info.get("failed") is not None:
        a(f"    tcpreplay failed packets: {tr_info['failed']:,}")

    a("\n[6] SIGNAL TRACES DURING PULSES vs BACKGROUND (5s window)")
    recs5 = scored[5]["recs"]
    pkt = packetin_rate_split(recs5, 5)
    a(f"    mean packet_in rate  pulse={pkt['pulse_mean']:,.0f} pkt/s "
      f"(n={pkt['pulse_n']})  gap={pkt['gap_mean']:,.0f} pkt/s (n={pkt['gap_n']})")
    a("    per-pulse M2 recovery (5s attack windows):")
    a(f"        {'rate':>5} {'n':>3} {'meanSynackRatio':>15} {'pooledSYN/SA':>13} "
      f"{'M1':>4} {'M2':>4} {'alert':>6}")
    for pb in pulse_breakdown(recs5, 5):
        a(f"        {pb['rate']:>5} {pb['n']:>3} {pb['mean_synack_ratio']:>15.2f} "
          f"{pb['pooled_ratio']:>13.2f} {pb['m1']:>4} {pb['m2']:>4} {pb['alert']:>6}")
    a("=" * 78)

    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    return "\n".join(L)


def report(csv_path, t_replay, tr_info, cpu, scored, ablation_mode):
    P = 6090873          # frames in pcap
    span = 482.66
    print("\n" + "=" * 78)
    print(f"BOUN LIVE-REPLAY SMOKE TEST — mode={ablation_mode}")
    print("=" * 78)

    # --- replay fidelity ---
    print("\n[ REPLAY ]")
    dur = tr_info.get("duration")
    sent = tr_info.get("sent")
    print(f"  pcap frames                 : {P:,}   pcap span : {span:.1f} s")
    print(f"  target avg replay rate      : {P / span:,.0f} pps "
          f"(TCP-only; note 19k figure was over all 9.3M rows incl. UDP)")
    if sent is not None and dur:
        print(f"  tcpreplay sent              : {sent:,} packets in {dur:.1f} s")
        print(f"  achieved avg replay rate    : {sent / dur:,.0f} pps")
        behind = dur - span
        verdict = ("KEPT UP" if behind <= span * 0.05
                   else f"BEHIND by {behind:+.1f} s")
        print(f"  kept native timing?         : {verdict}")
    if tr_info.get("actual_pps"):
        print(f"  tcpreplay 'Rated'           : {tr_info['actual_pps']:,.0f} pps")
    if tr_info.get("failed") is not None:
        print(f"  tcpreplay failed packets    : {tr_info['failed']:,}")

    # --- controller CPU ---
    print("\n[ CONTROLLER CPU ]  (Ryu process, % — can exceed 100 on multi-core)")
    print(f"  samples (1 Hz)              : {cpu['n']}")
    print(f"  Ryu CPU  mean / peak        : {cpu['mean']:.1f}%  /  {cpu['peak']:.1f}%")
    print(f"  system   mean / peak        : {cpu['sys_mean']:.1f}%  /  {cpu['sys_peak']:.1f}%")

    # --- detection ---
    print("\n[ DETECTION ]  (corrected stats-based wall->BOUN mapping)")
    print("  DR = alert attack windows / attack windows;  FPR = alert legit / legit;  "
          "alert = M1 AND M2 (FULL)")
    print(f"  {'window':>7} {'calib':>6} {'attackW':>8} {'legitW':>7} {'bound':>6} "
          f"{'M1@atk':>7} {'M2@atk':>7} {'DR':>9} {'FPR':>9} {'meanProc':>10}")
    for size in WINDOW_SIZES:
        s = scored[size]
        drh, drt = s["dr"]
        fph, fpt = s["fpr"]
        print(f"  {str(size)+'s':>7} {s['n_calib']:>6} {drt:>8} {fpt:>7} "
              f"{s['n_boundary']:>6} {s['m1_on_attack']:>7} {s['m2_on_attack']:>7} "
              f"{fmt_pct(drh, drt):>9} {fmt_pct(fph, fpt):>9} "
              f"{s['mean_proc_ms']:>8.2f}ms")

    # --- M2 recovery: per-pulse synack_ratio + packet_in rate (pulse vs gap) ---
    recs5 = scored[5]["recs"]
    pkt = packetin_rate_split(recs5, 5)
    print("\n[ M2 RECOVERY / CONTROL-PLANE RELIEF ]  (5s window)")
    print(f"  packet_in rate  pulse={pkt['pulse_mean']:,.0f} pkt/s  "
          f"gap(bkgd)={pkt['gap_mean']:,.0f} pkt/s   "
          f"(target: background dropped off the control plane => low gap)")
    print(f"  {'rate':>5} {'n':>3} {'meanSynackRatio':>15} {'pooledSYN/SA':>13} "
          f"{'meanPktIn/s':>12} {'M1':>4} {'M2':>4} {'alert':>6}   "
          f"(offline pulse ratio ~12-26)")
    for pb in pulse_breakdown(recs5, 5):
        print(f"  {pb['rate']:>5} {pb['n']:>3} {pb['mean_synack_ratio']:>15.2f} "
              f"{pb['pooled_ratio']:>13.2f} {pb['mean_pktin_rate']:>12,.0f} "
              f"{pb['m1']:>4} {pb['m2']:>4} {pb['alert']:>6}")

    # --- sanity dumps ---
    for size in WINDOW_SIZES:
        print(f"\n[ SANITY DUMP — {size}s window ]  "
              f"(calib cycles={scored[size]['n_calib']}; "
              f"warmup_cycles=3 => 120s expected under-warmed)")
        sanity_dump(scored[size]["recs"], size)

    # --- paper metrics block (persisted) ---
    paper_path = os.path.join(BOUN_LOG_DIR, "paper_metrics.txt")
    write_paper_metrics(paper_path, tr_info, cpu, scored, ablation_mode)

    print("\n[ OUTPUT ]")
    print(f"  detector CSV : {csv_path}")
    print(f"  paper metrics: {paper_path}")
    print("=" * 78)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        exp.die("Must run as root: sudo python3 experiment_boun.py [MODE] [run_id]")

    ablation_mode = (sys.argv[1].upper() if len(sys.argv) > 1 else "FULL")
    run_id = sys.argv[2] if len(sys.argv) > 2 else "boun"
    valid = {"FULL", "NO_MULTI_WINDOW", "NO_DUAL_MECH", "FIXED_THRESHOLD"}
    # NOOP (additive): detector-OFF CPU baseline. Same forwarding path (offload +
    # flood) but noop_detector.py does no parsing/counting/OAKF and writes no CSV,
    # so the Ryu-CPU delta vs a FULL run isolates the detector's own cost at the
    # native BOUN rate. Does NOT change OAKF params/detector/offload (task rule).
    noop = (ablation_mode == "NOOP")
    if noop:
        exp.DETECTOR_PY = os.path.join(exp.DETECTOR_DIR, "noop_detector.py")
    elif ablation_mode not in valid:
        exp.die(f"Unknown mode '{ablation_mode}'. Valid: {', '.join(sorted(valid))}, NOOP")

    os.makedirs(BOUN_LOG_DIR, exist_ok=True)
    # Estimated wall gap Ryu-launch -> replay-start, so the detector's phase
    # column flips near BOUN t=80. Scoring does not depend on this (the
    # post-processor uses wall-clock timestamps), it only keeps the log tidy.
    calib_secs = exp.RYU_STARTUP_SECS + exp.TOPO_SETTLE_SECS + 8 + FIRST_ATTACK_START

    exp.log(f"=== BOUN LIVE-REPLAY | mode={ablation_mode} run_id={run_id} ===")

    ryu_proc = None
    net = None
    cpu_samples: list = []
    stop_event = threading.Event()

    def cleanup():
        exp.log("Cleanup ...")
        stop_event.set()
        if net is not None:
            try:
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
        exp.log("Cleanup done.")

    try:
        exp.preflight_cleanup()
        ryu_proc = start_ryu_boun(ablation_mode, run_id, calib_secs)
        net = start_mininet_boun()

        # CIC-style forwarding: offload established (bare-ACK) background to the
        # dataplane so only new-flow SYN + real SYN-ACK reach the controller.
        install_forwarding_offload()

        # Start 1 Hz Ryu CPU sampling for the whole replay.
        sampler = threading.Thread(
            target=sample_cpu, args=(ryu_proc.pid, stop_event, cpu_samples), daemon=True
        )
        exp.log(f"Sampling Ryu CPU (pid={ryu_proc.pid}) at 1 Hz ...")
        sampler.start()

        t_replay, tr_log = replay_boun(net)

        exp.log(f"Post-replay drain ({POST_REPLAY_SECS} s) ...")
        time.sleep(POST_REPLAY_SECS)
        stop_event.set()
        sampler.join(timeout=5)

        # Shut the controller so it flushes/closes the CSV.
        exp.log("Stopping Ryu + Mininet ...")
        if ryu_proc.poll() is None:
            ryu_proc.terminate()
            try:
                ryu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                ryu_proc.kill()
        net.stop()
        net = None
        subprocess.run(["mn", "--clean"], capture_output=True)

        tr_info = parse_tcpreplay_log(tr_log)
        cpu = summarise_cpu(cpu_samples)

        # Always persist the raw 1 Hz CPU samples so the batch aggregator can
        # reconstruct ON (FULL) vs OFF (NOOP) mean/peak without parsing stdout.
        cpu_csv = os.path.join(BOUN_LOG_DIR, f"cpu_{run_id}_{ablation_mode}.csv")
        with open(cpu_csv, "w", newline="") as fh:
            cw = csv.writer(fh)
            cw.writerow(["elapsed_s", "ryu_cpu_pct", "system_cpu_pct"])
            cw.writerows(cpu_samples)

        if noop:
            span = 482.66
            dur = tr_info.get("duration")
            print("\n" + "=" * 78)
            print(f"BOUN NOOP CPU BASELINE — run_id={run_id}")
            print("=" * 78)
            print(f"  Ryu CPU  mean / peak : {cpu['mean']:.1f}% / {cpu['peak']:.1f}%")
            print(f"  system   mean / peak : {cpu['sys_mean']:.1f}% / {cpu['sys_peak']:.1f}%")
            print(f"  samples (1 Hz)       : {cpu['n']}")
            if dur:
                print(f"  replay               : {tr_info.get('sent'):,} pkts in {dur:.1f} s "
                      f"(stretch {dur/span:.2f}x)")
            print(f"  cpu samples csv      : {cpu_csv}")
            print("=" * 78)
            return

        csv_path = os.path.join(BOUN_LOG_DIR,
                                f"run_{run_id}_chunk_0_{ablation_mode}.csv")
        if not os.path.isfile(csv_path):
            exp.die(f"Detector CSV missing: {csv_path}")

        scored = score(csv_path, tr_log)
        report(csv_path, t_replay, tr_info, cpu, scored, ablation_mode)

    except Exception as exc:
        exp.log(f"[EXCEPTION] {exc}")
        cleanup()
        raise


if __name__ == "__main__":
    main()
