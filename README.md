# sdn-multi-window-ddos

Multi-timescale SYN-flood detector for Software-Defined Networks using an Online Adaptive Kalman Filter (OAKF). Built on Ryu (OpenFlow 1.3) and Mininet. Thesis project — Universiti Teknologi Malaysia, 2026.

---

## Architecture

```
3 observation windows  ×  3 traffic signals  =  9 OAKF instances
         │                       │
     5s / 30s / 120s      entropy / revisit-ratio / SYN:ACK-ratio
```

Each window–signal pair runs an independent OAKF that tracks the normal baseline and raises a flag when the residual exceeds 3 σ. Two mechanisms gate the final alert:

- **M1** — `entropy_anom OR revisit_anom` (source-diversity collapse or IP repetition)
- **M2** — `synack_anom` (SYN flood drives SYN:ACK ratio → 10 000)
- **Alert** — `M1 AND M2` (dual-mechanism confirmation suppresses false positives)

The OAKF skips zero-packet windows without updating filter state, and withholds anomaly flags for the first 3 non-zero cycles (warm-up). Non-anomalous measurements fold back into the filter; anomalous ones do not, preventing baseline corruption during an active attack.

---

## Results (CIC-DDoS2019, 30 chunks × 4 modes, 5 s window)

| Mode | Pooled DR | Per-chunk DR (mean ± SD) | FPR |
|:-----|:---------:|:------------------------:|:---:|
| **Full system** | **547/573 (95.5%)** | 95.5% ± 4.5% | 1/1289 (0.078%) |
| No multi-window | 545/574 (94.9%) | 94.9% ± 7.6% | 3/1289 (0.233%) |
| No dual-mech | 541/573 (94.4%) | 94.5% ± 8.7% | 611/1277 (47.8%) |
| Fixed threshold | 547/574 (95.3%) | 95.3% ± 5.0% | 0/1291 (0.000%) |

Processing latency (5 s window): **0.115 ms/cycle** on a commodity VM.

**Multi-window ablation:** removing the 30 s and 120 s windows raises per-chunk SD from 4.5% to 7.6%, confirming the longer windows stabilise detection variance.

**Dual-mechanism gate:** disabling M2 keeps DR at 94.4% but FPR explodes to 47.8%, demonstrating that entropy/revisit alone cannot discriminate SYN floods from bursty legitimate traffic in this topology.

**Sustained-attack validation (5-chunk PCAP, 419 s replay at 5 000 pps):**

| Window | DR | FPR |
|:------:|:--:|:---:|
| 5 s | 88/88 (100%) | 1/44 (2.3%) |
| 30 s | 15/15 (100%) | 0/7 (0.0%) |
| 120 s | 2/4 (50%) | 0/1 (0.0%) |

The 120 s window yields 50% DR because only one calibration cycle fires before the attack, leaving the OAKF in warm-up for the first two attack cycles. Detection is 100% from cycle 3 onward. A calibration period ≥ 240 s would give the 120 s OAKF two training cycles and eliminate this effect.

---

## Repository layout

```
sdn-thesis/
├── harness/
│   ├── detector/
│   │   ├── multi_window_detector_v2.py   Ryu app — WindowState, OAKF, CSV, ablation modes
│   │   └── oakf.py                       OAKF implementation (Ahmad & Alkhammash 2024)
│   ├── traffic/
│   │   └── legit_traffic_gen.py          Raw-socket calibration traffic (20 pps, 20 IPs)
│   ├── scripts/
│   │   └── experiment.py                 Full trial lifecycle (Ryu → Mininet → tcpreplay)
│   └── analysis/
│       └── compute_metrics.py            Aggregates CSVs → DR / FPR / proc-time tables
├── topology/
│   └── tree_5sw_20h.py                   5-switch, 20-host OpenFlow 1.3 topology
├── run_all.sh                            Batch runner: 30 chunks × 4 modes = 120 trials
├── run_long_test.sh                      Sustained-attack validation (5-chunk PCAP)
├── make_thesis_figures.py                Generates thesis figures 4.1–4.7
├── appendix_tables.py                    Generates Appendix B per-chunk tables
├── analyze_long_test.py                  Analysis for the sustained-attack run
├── generate_report.py                    Per-run HTML dashboard
└── logs/
    └── figures/                          Thesis figures (figure_4_1.png … figure_4_7.png)
```

> **Note:** `chunks/` (30 × ~37 MB PCAPs) and `datasets/` are excluded by `.gitignore`.
> Download CIC-DDoS2019 and split into 30 equal-packet chunks to reproduce.

---

## Prerequisites

- Ubuntu 20.04 / 22.04, Python 3.8+
- Mininet, Open vSwitch
- Ryu SDN framework in a virtualenv at `~/ryu-env/`
- `tcpreplay`, `capinfos`, `mergecap` (Wireshark suite)
- Root access (Mininet requires it)

---

## Running a single trial

```bash
source ~/ryu-env/bin/activate
CALIBRATION_SECS=150 ATTACK_SECS=90 sudo -E python3 \
    ~/sdn-thesis/harness/scripts/experiment.py <chunk_id> <MODE> <run_id>
```

`MODE`: `FULL` | `NO_MULTI_WINDOW` | `NO_DUAL_MECH` | `FIXED_THRESHOLD`

Output: `logs/run_<run_id>_chunk_<chunk_id>_<MODE>.csv`

---

## Running the full 120-trial batch

```bash
sudo bash ~/sdn-thesis/run_all.sh
```

Runs all 30 chunks × 4 ablation modes sequentially (~12 hours).
Progress is logged to `logs/batch_progress.log`.

---

## Sustained-attack validation (120 s window)

Build the 5-chunk long-attack PCAP once:

```bash
mergecap -w ~/sdn-thesis/chunks/long_attack_5chunk.pcap \
    ~/sdn-thesis/chunks/chunk_00000.pcap \
    ~/sdn-thesis/chunks/chunk_00001.pcap \
    ~/sdn-thesis/chunks/chunk_00002.pcap \
    ~/sdn-thesis/chunks/chunk_00003.pcap \
    ~/sdn-thesis/chunks/chunk_00004.pcap
```

Then run and analyse:

```bash
sudo -E bash ~/sdn-thesis/run_long_test.sh
python3 ~/sdn-thesis/analyze_long_test.py
```

---

## Metrics and figures

```bash
# Aggregate DR / FPR / proc-time across all CSVs
python3 ~/sdn-thesis/harness/analysis/compute_metrics.py

# Appendix B tables (per-chunk DR, per-mode summary, per-window)
python3 ~/sdn-thesis/appendix_tables.py

# Thesis figures 4.1–4.7 (300 dpi PNG → logs/figures/)
python3 ~/sdn-thesis/make_thesis_figures.py

# Interactive HTML dashboard
python3 ~/sdn-thesis/generate_report.py
```

---

## CSV column reference (detector output)

| Col | Name | Description |
|----:|:-----|:------------|
| 1 | timestamp | Unix timestamp at window-cycle end |
| 2 | elapsed_s | Seconds since detector start |
| 3 | phase | `calibration` / `attack` / `post` |
| 4 | window | `5s` / `30s` / `120s` |
| 5–8 | packets, unique_ips, syn, synack | Raw window counts |
| 9–11 | entropy, entropy_thresh, entropy_anom | Shannon entropy signal |
| 12–14 | revisit, revisit_thresh, revisit_anom | IP revisit-ratio signal |
| 15–17 | synack_ratio, synack_thresh, synack_anom | SYN:ACK-ratio signal |
| 18 | mech1 | M1 flag (`entropy_anom OR revisit_anom`) |
| 19 | mech2 | M2 flag (`synack_anom`) |
| 20 | alert | Final alert (`M1 AND M2`, or M1 alone in `NO_DUAL_MECH`) |
| 21 | proc_time_ms | Per-cycle processing latency |
| 22–24 | run_id, chunk_id, ablation_mode | Run metadata |

---

## Citation

OAKF implementation based on:
Ahmad, M. & Alkhammash, M. (2024). *Online Adaptive Kalman Filtering for Real-Time Anomaly Detection in Wireless Sensor Networks.*

Dataset:
Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* CIC-DDoS2019.

---

## License

MIT — see `LICENSE`.
