#!/usr/bin/env python3
"""
experiment.py  —  Mininet-native experiment runner.

Owns the full trial lifecycle:
  1. Pre-flight cleanup (mn --clean)
  2. Start Ryu controller (subprocess, Ryu venv)
  3. Build and start Mininet topology (via tree_5sw_20h.build_topology)
  4. Run legitimate traffic on h1 for CALIBRATION_SECS
  5. Inject attack PCAP on h16 via tcpreplay (h16-eth0 namespace)
  6. Post-attack wait for last window cycles to fire
  7. Graceful shutdown

Usage (must run as root — Mininet requires it):
    sudo python3 experiment.py <chunk_id> [ABLATION_MODE] [run_id]

    chunk_id     : integer 1-30
    ABLATION_MODE: FULL | NO_MULTI_WINDOW | NO_DUAL_MECH | FIXED_THRESHOLD
    run_id       : label for CSV filenames (default: FULL_001 etc.)

Environment overrides:
    CALIBRATION_SECS (default 150)
    ATTACK_SECS      (default 90)   — safety margin over actual ~84 s
    RYU_VENV         (default ~/ryu-env)

Why Mininet-native instead of shell scripts?
    tree_5sw_20h.py opens a CLI(net) interactive shell — you can't control
    it from a parent shell script. Running via the Python API lets us call
    net.start() / net.stop() programmatically and use h.cmd() to launch
    traffic generators and tcpreplay inside each host's network namespace.
    The attacker interface is simply h16-eth0 (h16's own NIC) — no need to
    know the switch-side port name.
"""

import os
import shutil
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

THESIS_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOPOLOGY_DIR = os.path.join(THESIS_DIR, "topology")
HARNESS_DIR  = os.path.join(THESIS_DIR, "harness")
DETECTOR_DIR = os.path.join(HARNESS_DIR, "detector")
TRAFFIC_GEN  = os.path.join(HARNESS_DIR, "traffic", "legit_traffic_gen.py")
CHUNKS_DIR   = os.path.join(THESIS_DIR, "chunks")
LOG_DIR      = os.path.join(THESIS_DIR, "logs")

RYU_VENV     = os.environ.get("RYU_VENV", os.path.join(os.path.expanduser("~sdnuser"), "ryu-env"))
_venv_ryu    = os.path.join(RYU_VENV, "bin", "ryu-manager")
RYU_MANAGER  = _venv_ryu if os.path.isfile(_venv_ryu) else (shutil.which("ryu-manager") or _venv_ryu)
DETECTOR_PY  = os.path.join(DETECTOR_DIR, "multi_window_detector_v2.py")

CALIBRATION_SECS  = float(os.environ.get("CALIBRATION_SECS", 150))
ATTACK_SECS       = float(os.environ.get("ATTACK_SECS", 90))
POST_ATTACK_SECS  = int(os.environ.get("POST_ATTACK_SECS", 35))
RYU_STARTUP_SECS  = 12   # time for Ryu to bind port 6653
TOPO_SETTLE_SECS  = 15   # time for all OF handshakes to complete


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts() -> str:
    return time.strftime("%H:%M:%S")


def log(msg: str):
    print(f"[{ts()}] {msg}", flush=True)


def die(msg: str):
    log(f"[ERROR] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def preflight_cleanup():
    log("Pre-flight: mn --clean ...")
    subprocess.run(["mn", "--clean"], capture_output=True)
    time.sleep(3)


# ---------------------------------------------------------------------------
# Ryu controller
# ---------------------------------------------------------------------------

def start_ryu(chunk_id: int, ablation_mode: str, run_id: str) -> subprocess.Popen:
    if not os.path.isfile(RYU_MANAGER):
        die(f"ryu-manager not found at {RYU_MANAGER}\n"
            f"    Set RYU_VENV env var to your virtualenv path.")
    if not os.path.isfile(DETECTOR_PY):
        die(f"Detector not found: {DETECTOR_PY}")

    # The detector starts its internal clock at Ryu launch, but Mininet takes
    # RYU_STARTUP_SECS + TOPO_SETTLE_SECS to connect. Add this offset so the
    # detector's "calibration" phase label ends at the same wall-clock moment
    # that the actual calibration (legit traffic) ends in experiment.py.
    startup_offset = RYU_STARTUP_SECS + TOPO_SETTLE_SECS + 43  # =70, accounts for 5s Mininet build, 8s pre-attack cleanup, 30s drain
    detector_calib = int(CALIBRATION_SECS) + startup_offset

    env = os.environ.copy()
    env.update({
        "RUN_ID":            run_id,
        "CHUNK_ID":          str(chunk_id),
        "ABLATION_MODE":     ablation_mode,
        "CALIBRATION_SECS":  str(detector_calib),
        "ATTACK_SECS":       str(int(ATTACK_SECS) + 5),   # small safety margin
        "LOG_DIR":           LOG_DIR,
        # Ensure Ryu finds oakf.py
        "PYTHONPATH":        DETECTOR_DIR + ":" + env.get("PYTHONPATH", ""),
    })
    log(f"Detector calibration window = {detector_calib}s "
        f"(experiment {int(CALIBRATION_SECS)}s + {startup_offset}s startup offset)")

    ryu_log = os.path.join(LOG_DIR, f"ryu_{run_id}_chunk{chunk_id:05d}_{ablation_mode}.log")
    log(f"Starting Ryu → {ryu_log}")

    ryu_proc = subprocess.Popen(
        [RYU_MANAGER, "--verbose", "--log-file", ryu_log, DETECTOR_PY],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    log(f"Ryu PID={ryu_proc.pid}. Waiting {RYU_STARTUP_SECS} s ...")
    time.sleep(RYU_STARTUP_SECS)

    if ryu_proc.poll() is not None:
        die(f"Ryu exited early (code {ryu_proc.returncode}). See {ryu_log}")

    return ryu_proc


# ---------------------------------------------------------------------------
# Mininet topology
# ---------------------------------------------------------------------------

def start_mininet():
    sys.path.insert(0, TOPOLOGY_DIR)
    from tree_5sw_20h import build_topology   # noqa: PLC0415

    log("Building Mininet topology ...")
    net = build_topology()
    net.start()
    log(f"Topology started. Waiting {TOPO_SETTLE_SECS} s for OF handshakes ...")
    time.sleep(TOPO_SETTLE_SECS)

    # Drop incoming TCP SYN from non-Mininet IPs on legitimate hosts h1-h15.
    # Without this, Mininet hosts send SYN-ACK back to the spoofed source IPs
    # in the SYN flood, depressing the synack_ratio signal and preventing M2
    # from firing. With this rule, only SYN from 10.0.0.0/24 get a reply,
    # so the detector sees a high SYN/ACK ratio during the flood as designed.
    log("Configuring iptables on h1-h15 (block SYN-ACK to non-Mininet IPs) ...")
    for i in range(1, 16):
        h = net.get(f"h{i}")
        h.cmd("iptables -A INPUT -p tcp --syn -s 10.0.0.0/24 -j ACCEPT")
        h.cmd("iptables -A INPUT -p tcp --syn -j DROP")
        h.cmd("iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK ! -d 10.0.0.0/24 -j DROP")
        # Zero retries so calibration-time half-open connections die immediately
        # when calibration ends, rather than retransmitting SYN-ACK into the attack phase.
        h.cmd("sysctl -w net.ipv4.tcp_synack_retries=0 > /dev/null 2>&1")

    return net


# ---------------------------------------------------------------------------
# Legitimate traffic (calibration phase)
# ---------------------------------------------------------------------------

def start_legit_traffic(net, duration: float):
    """
    Run legit_traffic_gen.py on h1 for raw-socket calibration traffic.
    20 pps (10 SYN + 10 SYN-ACK/s) from 20 IPs keeps the OAKF baseline
    stable while keeping the Ryu packet_in queue backlog small enough for
    the 30s pre-attack drain to clear it.

    iperf3 was removed: each data packet hits the OVS table-miss rule and
    generates ~5 packet_in events across 5 switches. At 250 pps × 5 × 150s
    = 187,500 queued events, the 30s drain cannot clear the backlog before
    the attack starts, causing the first attack cycle to see synack_count > 0
    and miss M2.
    """
    log(f"Starting legitimate traffic ({duration:.0f} s) ...")
    h1 = net.get("h1")
    h1.cmd(f"python3 {TRAFFIC_GEN} {int(duration)} > /dev/null 2>&1 &")
    log("Legitimate traffic running: raw-socket gen on h1 at 20 pps.")


def stop_legit_traffic(net):
    log("Stopping legitimate traffic ...")
    try:
        h1 = net.get("h1")
        h1.cmd("pkill -f legit_traffic_gen 2>/dev/null")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Attack injection
# ---------------------------------------------------------------------------

def inject_attack(net, chunk_id: int) -> float:
    """
    Run tcpreplay inside h16's network namespace on h16-eth0.
    Returns: wall-clock time the attack started.
    Set SDN_ATTACK_PCAP to override the default chunk-based pcap path.
    """
    custom_pcap = os.environ.get("SDN_ATTACK_PCAP", "").strip()
    if custom_pcap:
        chunk_file = custom_pcap
    else:
        chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{chunk_id:05d}.pcap")
    if not os.path.isfile(chunk_file):
        die(f"Attack PCAP not found: {chunk_file}")

    h16 = net.get("h16")
    log(f"ATTACK START: tcpreplay {chunk_file} on h16-eth0 at 5000 pps ...")
    t_attack = time.time()

    # cmd() blocks until the command finishes — perfect for tcpreplay.
    h16.cmd(
        f"tcpreplay --intf1=h16-eth0 --pps=5000 {chunk_file}"
        f" > {LOG_DIR}/tcpreplay_chunk{chunk_id:05d}.log 2>&1"
    )
    t_end = time.time()
    log(f"Attack injection done. Duration: {t_end - t_attack:.1f} s")
    return t_attack


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        die("Must run as root: sudo python3 experiment.py ...")

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <chunk_id> [MODE] [run_id]")
        sys.exit(1)

    chunk_id      = int(sys.argv[1])
    ablation_mode = sys.argv[2].upper() if len(sys.argv) > 2 else "FULL"
    chunk_pad     = f"{chunk_id:05d}"
    run_id        = sys.argv[3] if len(sys.argv) > 3 else f"{ablation_mode}_{chunk_pad}"

    valid_modes = {"FULL", "NO_MULTI_WINDOW", "NO_DUAL_MECH", "FIXED_THRESHOLD"}
    if ablation_mode not in valid_modes:
        die(f"Unknown mode '{ablation_mode}'. Valid: {', '.join(sorted(valid_modes))}")

    os.makedirs(LOG_DIR, exist_ok=True)

    log(f"=== EXPERIMENT | chunk={chunk_id} mode={ablation_mode} run_id={run_id} ===")
    log(f"    calibration={CALIBRATION_SECS:.0f}s  attack≈{ATTACK_SECS:.0f}s  "
        f"post={POST_ATTACK_SECS}s")

    ryu_proc = None
    net = None

    def cleanup(signum=None, frame=None):
        log("Cleanup ...")
        if net:
            try:
                stop_legit_traffic(net)
            except Exception:
                pass
            try:
                net.stop()
            except Exception:
                pass
        if ryu_proc and ryu_proc.poll() is None:
            ryu_proc.terminate()
            try:
                ryu_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ryu_proc.kill()
        subprocess.run(["mn", "--clean"], capture_output=True)
        log("Cleanup done.")

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    try:
        # 1 — Pre-flight
        preflight_cleanup()

        # 2 — Ryu
        ryu_proc = start_ryu(chunk_id, ablation_mode, run_id)

        # 3 — Mininet
        net = start_mininet()

        # 4 — Calibration
        log(f"CALIBRATION START ({CALIBRATION_SECS:.0f} s) ...")
        start_legit_traffic(net, CALIBRATION_SECS)
        time.sleep(CALIBRATION_SECS)
        stop_legit_traffic(net)
        log("Calibration complete.")

        # 4b — Flush half-open TCP connections before attack.
        log("Flushing SYN_RECV connections on h1-h15 ...")
        for i in range(1, 16):
            h = net.get(f"h{i}")
            h.cmd("ss -K state syn-recv 2>/dev/null; true")
        time.sleep(3)
        log("TCP connection state cleared.")

        # Block ALL outgoing SYN-ACK on h1-h15 before attack.
        # ss -K may not reliably kill SYN_RECV sockets on this kernel.
        # An OUTPUT chain DROP is the guaranteed backstop: no SYN-ACK
        # retransmission from h1-h15 can reach the OVS switch or controller.
        # Calibration OAKF baseline is already captured; blocking here only
        # affects the attack phase, which is what we want.
        log("Blocking all outgoing SYN-ACK on h1-h15 ...")
        for i in range(1, 16):
            h = net.get(f"h{i}")
            h.cmd("iptables -I OUTPUT 1 -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP")
        time.sleep(2)
        log("SYN-ACK blocked. Attack phase will see zero SYN-ACK from h1-h15.")

        # Install OVS dataplane DROP rule for SYN-ACK on every switch (s1-s5).
        # Priority=100 supersedes the table-miss rule (priority=0), so SYN-ACK
        # packets are silently dropped before generating a packet_in event.
        # Result: controller sees SYN but 0 SYN-ACK → synack_ratio = 10000.
        log("Installing OVS SYN-ACK DROP rules on s1-s5 ...")
        for sw in [f"s{i}" for i in range(1, 6)]:
            ret = subprocess.run(
                ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", sw,
                 "tcp,tcp_flags=+syn+ack,priority=100,action=drop"],
                capture_output=True, text=True,
            )
            if ret.returncode != 0:
                log(f"  [WARN] ovs-ofctl {sw}: {ret.stderr.strip()}")
        time.sleep(1)
        log("OVS SYN-ACK DROP rules installed on s1-s5.")

        # Drain Ryu's packet_in event queue before starting the attack.
        # During calibration, legit_traffic_gen sends SYN-ACK via raw sockets;
        # Ryu OFPP_FLOODs each one, queuing ~40s of SYN-ACK packet_in events.
        # The iptables/OVS DROP rules stop NEW SYN-ACK but cannot evict already-
        # queued events. Without this sleep, the first 3 attack cycles see
        # synack_count > 0 (backlog draining), so synack_ratio stays near 1
        # and M2 never fires → missed detections. After 30s, the WindowState
        # resets 6 times (every 5s), flushing all backlog counts to zero.
        log("Draining Ryu packet_in backlog (30 s) ...")
        time.sleep(30)
        log("Drain complete. synack_count should now be zero.")

        # 5 — Attack
        inject_attack(net, chunk_id)

        # 6 — Post-attack wait
        log(f"Post-attack wait ({POST_ATTACK_SECS} s) ...")
        time.sleep(POST_ATTACK_SECS)

        # 7 — Shutdown
        log("Shutting down ...")
        ryu_proc.terminate()
        ryu_proc.wait(timeout=10)
        net.stop()

        csv_name = f"run_{run_id}_chunk_{chunk_id}_{ablation_mode}.csv"
        log(f"=== TRIAL COMPLETE ===")
        log(f"    CSV:     {LOG_DIR}/{csv_name}")
        log(f"    Ryu log: {LOG_DIR}/ryu_{run_id}_chunk{chunk_id:03d}_{ablation_mode}.log")

    except Exception as exc:
        log(f"[EXCEPTION] {exc}")
        cleanup()
        raise


if __name__ == "__main__":
    main()
