# Multi-Timescale TCP SYN Flood Detection in SDN

A real-time TCP SYN flood detector for Ryu (OpenFlow 1.3) controllers, evaluated in a Mininet testbed against the CIC-DDoS2019 benchmark. The detector combines Online Adaptive Kalman Filters (OAKF) across three time windows (5 s / 30 s / 120 s) and three signals (Shannon entropy, IP revisit rate, SYN/ACK ratio) with a dual-mechanism alert logic to achieve high detection rate with low false positives — without any machine-learning inference on the controller.

Developed as part of an undergraduate thesis.

**Final experimental results (120 trials: 30 chunks × 4 ablation modes, CIC-DDoS2019):**

| Mode | DR (5 s window) | FPR (5 s window) |
|------|----------------|-----------------|
| FULL (3 windows × dual-mechanism) | **95.5%** | **0.078%** |
| NO_MULTI_WINDOW (5 s only) | — | — |
| NO_DUAL_MECH (single mechanism) | — | — |
| FIXED_THRESHOLD (no OAKF) | — | — |

Target: DR ≥ 95%, FPR < 0.97%. Per-cycle processing time: ~0.115 ms (well under the 5 s window budget).

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Repository Setup](#2-repository-setup)
3. [Environment Setup](#3-environment-setup)
4. [Dataset Preparation](#4-dataset-preparation)
5. [Running a Single Trial](#5-running-a-single-trial)
6. [Running the Full Batch](#6-running-the-full-batch)
7. [Generating Reports](#7-generating-reports)
8. [Ablation Modes](#8-ablation-modes)
9. [Known Issues and Design Decisions](#9-known-issues-and-design-decisions)

---

## 1. System Requirements

The experiment is designed for a **bare-metal Ubuntu 20.04 LTS** host. A VM works but network emulation performance degrades under nested virtualisation; Mininet's `tc` shaping and OVS kernel module behave unpredictably inside some hypervisors.

**Tested configuration:**
- OS: Ubuntu 20.04.6 LTS (kernel 5.15.0)
- CPU: Intel i7-12700H (14 cores)
- RAM: 32 GB DDR5
- Storage: ~4 GB free for dataset chunks + logs

**Required packages** (all via apt unless noted):

| Component | Version tested |
|-----------|---------------|
| Python    | 3.8.10        |
| Ryu       | 4.30 (apt)    |
| Mininet   | 2.3.0         |
| Open vSwitch | 2.13.8     |
| tcpreplay | 4.3.2         |
| editcap (Wireshark) | 3.2.3 |
| hping3    | 3.0.0         |

Install system dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip \
    ryu-bin mininet openvswitch-switch \
    tcpreplay wireshark-common hping3
```

Ryu is installed as a system package (`/usr/bin/ryu-manager`). The repository includes a `ryu-env` directory that is used for Python path isolation but does **not** contain a separate Ryu installation — use the system binary.

---

## 2. Repository Setup

```bash
git clone https://github.com/aimannurzharfan/sdn-multi-window-ddos.git ~/sdn-thesis
cd ~/sdn-thesis
```

Directory layout after cloning:

```
sdn-thesis/
├── harness/
│   ├── detector/
│   │   ├── multi_window_detector_v2.py   # Ryu app (OAKF, CSV output, ablation)
│   │   └── oakf.py                        # OAKF implementation
│   ├── scripts/
│   │   └── experiment.py                  # Full trial lifecycle
│   ├── traffic/
│   │   └── legit_traffic_gen.py           # Raw-socket calibration traffic
│   └── analysis/
│       └── compute_metrics.py             # Aggregates CSV → DR/FPR/proc-time
├── topology/
│   └── tree_5sw_20h.py                    # 5 switches, 20 hosts
├── chunks/                                # Populated by dataset preparation (step 4)
│   ├── chunk_00000.pcap
│   └── … chunk_00029.pcap
├── logs/                                  # Trial outputs (created at runtime)
├── run_all.sh                             # Batch runner (120 trials)
├── generate_report.py                     # HTML report generator
└── scripts/
    └── check_environment.sh               # Version check
```

---

## 3. Environment Setup

Verify all dependencies are present:

```bash
bash ~/sdn-thesis/scripts/check_environment.sh
```

Enable IP forwarding and load the OVS kernel module (required for Mininet):

```bash
sudo modprobe openvswitch
sudo sysctl -w net.ipv4.ip_forward=1
```

The experiment scripts set kernel parameters on individual Mininet hosts at runtime; no persistent system changes are needed beyond the above.

---

## 4. Dataset Preparation

The experiment uses the **CIC-DDoS2019** dataset, specifically the SYN flood capture from Saturday 11 March 2018 (`SAT-03-11-2018`). This file is not included in the repository due to size.

**Download:** Obtain the dataset from the Canadian Institute for Cybersecurity and locate the raw PCAP for SAT-03-11-2018. Place it at:

```
~/sdn-thesis/datasets/PCAP-03-11.pcap
```

**Extract SYN packets only** (removes non-SYN traffic, ~955 MB result):

```bash
editcap -r ~/sdn-thesis/datasets/PCAP-03-11.pcap \
        ~/sdn-thesis/datasets/syn_only.pcap \
        1-12000000   # adjust range to cover all SYN packets
```

A more targeted extraction using tcpdump to keep only TCP SYN packets (flag bit 0x002 set, ACK clear):

```bash
tcpdump -r ~/sdn-thesis/datasets/PCAP-03-11.pcap \
        -w ~/sdn-thesis/datasets/syn_only.pcap \
        'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
```

**Split into 30 chunks** of 418,853 packets each (~37 MB, ~84 s at 5,000 pps):

```bash
mkdir -p ~/sdn-thesis/chunks
editcap -c 418853 ~/sdn-thesis/datasets/syn_only.pcap \
        ~/sdn-thesis/chunks/chunk_.pcap

# Rename to zero-padded five-digit format expected by run_all.sh
for i in $(seq 0 29); do
    old=$(printf 'chunk_%d.pcap' $((i + 1)))
    new=$(printf 'chunk_%05d.pcap' "$i")
    mv ~/sdn-thesis/chunks/"$old" ~/sdn-thesis/chunks/"$new" 2>/dev/null || true
done
```

Verify:

```bash
ls ~/sdn-thesis/chunks/chunk_*.pcap | wc -l   # should print 30
```

---

## 5. Running a Single Trial

Each trial: starts Mininet + Ryu, runs 150 s calibration traffic, injects one PCAP chunk as a SYN flood for 90 s, stops everything, and writes a CSV to `logs/`.

```bash
source ~/ryu-env/bin/activate   # sets PYTHONPATH; Ryu itself is system-wide
CALIBRATION_SECS=150 ATTACK_SECS=90 sudo -E python3 \
    ~/sdn-thesis/harness/scripts/experiment.py \
    <chunk_id> <MODE> <run_id>
```

- `chunk_id`: integer 0–29, selects `chunks/chunk_<NNNNN>.pcap`
- `MODE`: one of `FULL`, `NO_MULTI_WINDOW`, `NO_DUAL_MECH`, `FIXED_THRESHOLD`
- `run_id`: arbitrary string label for the output files

Example — chunk 0, full detector, manual run:

```bash
CALIBRATION_SECS=150 ATTACK_SECS=90 sudo -E python3 \
    ~/sdn-thesis/harness/scripts/experiment.py 0 FULL manual_c00
```

Output files written to `logs/`:

```
logs/run_manual_c00_chunk_0_FULL.csv    # per-cycle detector data
logs/ryu_manual_c00_chunk0_FULL.log     # Ryu controller log
```

**Checking results** (DR and FPR for the 5 s window):

```bash
awk -F',' 'NR>1 && $4=="5s" {
    att+=($3=="attack"); det+=($3=="attack" && $20==1);
    cal+=($3=="calibration"); fp+=($3=="calibration" && $20==1)
} END {printf "DR=%d/%d=%.1f%%  FPR=%d/%d=%.1f%%\n",
       det,att,100*det/att, fp,cal,100*fp/cal}' \
    ~/sdn-thesis/logs/run_manual_c00_chunk_0_FULL.csv
```

Expected: DR ≥ 95%, FPR < 0.97%.

**Phase timing.** The detector's elapsed clock starts at Ryu launch. Actual traffic starts ~70 s later (12 s Ryu startup + 15 s OF handshakes + 5 s Mininet overhead + 8 s pre-attack cleanup + 30 s drain period). `startup_offset = 70` is baked into `experiment.py` so the detector's calibration-end boundary aligns with the first real attack packet.

---

## 6. Running the Full Batch

The batch runner executes all 120 trials (30 chunks × 4 ablation modes) sequentially, logging each trial's outcome. Estimated wall time is ~12 hours.

```bash
sudo bash ~/sdn-thesis/run_all.sh
```

The script performs pre-flight checks (verifies `experiment.py` exists and all 30 PCAPs are present) before starting. If a trial fails it logs the exit code and continues — the batch will not abort on a single failure.

Progress is streamed to both stdout and `logs/batch_progress.log`. To monitor a running batch:

```bash
tail -f ~/sdn-thesis/logs/batch_progress.log
```

On completion, `logs/` will contain up to 120 CSVs and 120 Ryu logs.

---

## 7. Generating Reports

After the batch completes, generate a self-contained HTML report:

```bash
python3 ~/sdn-thesis/generate_report.py
```

This reads all `logs/run_*.csv` files and writes:

- `logs/report.html` — main summary: stat bar, 4-mode ablation comparison table, 3-window FULL breakdown, per-chunk DR heatmap grid, file inventory
- `logs/report_chunk_NN.html` — one per chunk with data: mode comparison (5 s window), FULL window breakdown (5 s/30 s/120 s), and a full signal trace showing every detector cycle (phase, packet counts, entropy, revisit ratio, SYN/ACK ratio, anomaly flags, alert status)

Open `logs/report.html` in any browser. Per-chunk links are in the heatmap grid.

For a plain-text metrics table (suitable for copy-paste into a thesis):

```bash
python3 ~/sdn-thesis/harness/analysis/compute_metrics.py
```

This also writes `logs/metrics_summary.csv` and `logs/per_run_metrics.csv`.

---

## 8. Ablation Modes

Four modes let you isolate the contribution of each design component:

| Mode | Description |
|------|-------------|
| `FULL` | All features: 3 windows × 3 signals × dual-mechanism alert |
| `NO_MULTI_WINDOW` | Single window (5 s only); all signals and dual-mechanism active |
| `NO_DUAL_MECH` | All three windows; single mechanism (M1 OR M2 triggers alert) |
| `FIXED_THRESHOLD` | Static thresholds instead of OAKF adaptive thresholds |

The mode is passed as the second argument to `experiment.py` and is also embedded in the output CSV filenames and the `ablation_mode` column of every row. The detector app (`multi_window_detector_v2.py`) reads the `ABLATION_MODE` environment variable set by `experiment.py` and branches accordingly.

---

## 9. Known Issues and Design Decisions

**Why remove iperf3 from calibration traffic?**
iperf3 data packets are forwarded by OVS via `OFPP_FLOOD`, generating a `packet_in` event on every switch for every packet. With 5 switches and 250 data pps, a 150 s calibration phase creates ~187,500 queued events in Ryu's gevent hub. These drain into the detector after traffic stops, contaminating the first attack cycles with legitimate-looking packet counts. The calibration generator (`legit_traffic_gen.py`) uses raw sockets at 20 pps instead — the resulting ~7,500-event backlog drains completely within the 30 s pre-attack drain period.

**Why 30 s drain period?**
After the pre-attack cleanup (OVS DROP rules, iptables flush), the Ryu controller still has queued `packet_in` events from calibration. If the attack starts immediately, those events are processed during what the detector marks as the attack phase, inflating apparent traffic volume and delaying anomaly detection. The 30 s sleep (in `experiment.py`) ensures the queue is empty before attack injection.

**Why `startup_offset = 70`?**
The detector's elapsed-time clock starts when `ryu-manager` launches. The actual first calibration packet arrives ~70 s later (Ryu startup + OpenFlow handshake + Mininet link-up + pre-attack OVS setup + drain). The offset shifts the `calib_end` boundary forward so the phase labels in the CSV correspond to actual traffic phases, not Ryu uptime.

**SYNACK_RATIO_CAP = 10000.0**
During a SYN flood, `synack_count` drops to zero (the attacker sends only SYN packets). Dividing by zero is avoided by returning the cap value instead. The OAKF treats this as an extreme high-side anomaly, which is correct: a ratio of 10,000 is far above any legitimate baseline.

**CSV output path under sudo**
Both `experiment.py` and `multi_window_detector_v2.py` derive their output directory from `__file__` rather than `os.path.expanduser("~")`. This is necessary because `sudo` sets `HOME=/root`, which would cause CSVs to be written to `/root/sdn-thesis/logs/` instead of the user's home. The `LOG_DIR` env var is also passed explicitly from `experiment.py` to `ryu-manager` as a belt-and-suspenders measure.

**Ryu binary location**
The system Ryu package installs to `/usr/bin/ryu-manager`. The repository contains a `~/ryu-env` virtual environment that sets `PYTHONPATH` for the harness Python code but does not contain a Ryu installation. Always run `ryu-manager` directly or via `sudo -E` (which inherits the activated venv's `PYTHONPATH`).

**Root requires `sudo -E`**
Mininet requires root for network namespace and OVS manipulation. The `-E` flag preserves the activated virtual environment's `PYTHONPATH` so the harness modules are importable under `sudo`.

---

## License

MIT License. See `LICENSE`.
