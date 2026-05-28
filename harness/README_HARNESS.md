# Experiment Harness — Setup and Run Order

## Directory layout (inside ~/sdn-thesis/ on the VM)

```
~/sdn-thesis/
  chunks/                     chunk_001.pcap ... chunk_030.pcap  (already present)
  topology/                   tree_5sw_20h.py                    (already present)
  harness/
    detector/
      multi_window_detector_v2.py   <- upgraded detector (this session)
      oakf.py                       <- unchanged from repo
    traffic/
      legit_traffic_gen.py          <- legitimate traffic (this session)
    scripts/
      run_one_chunk.sh              <- single trial runner
      batch_run.sh                  <- 30-chunk batch runner
      ablation_run.sh               <- all 4 modes x 30 chunks
    analysis/
      compute_metrics.py            <- DR / FPR / proc-time aggregator
  logs/                             <- created automatically
```

## Step 0 — Copy harness to VM

Once the shared folder is working:
```bash
cp -r /media/sf_SDNResearch/harness ~/sdn-thesis/
# Copy the upgraded oakf.py (unchanged) alongside the new detector:
cp ~/sdn-thesis/harness/detector/oakf.py ~/sdn-thesis/harness/detector/  # already there if cloned
chmod +x ~/sdn-thesis/harness/scripts/*.sh
```

Also copy oakf.py if it is not already in harness/detector/:
```bash
cp ~/sdn-thesis/detector/oakf.py ~/sdn-thesis/harness/detector/
```

## Step 1 — Empirically confirm attack interface

Before any run, verify the attacker interface name:
```bash
sudo mn --custom ~/sdn-thesis/topology/tree_5sw_20h.py --test none &
# In the Mininet CLI:
mininet> s5 ovs-ofctl show s5
# Look for eth7 or similar. Note the name.
# Then set ATTACK_IFACE in run_one_chunk.sh if different from s5-eth7.
```

## Step 2 — Smoke test with a single chunk

```bash
sudo bash ~/sdn-thesis/harness/scripts/run_one_chunk.sh 1 FULL test01
# Check output:
cat ~/sdn-thesis/logs/run_test01_chunk_1_FULL.csv | head -5
```

The CSV should have rows with phase="calibration" and phase="attack".

## Step 3 — Run all 30 chunks (FULL mode)

Recommended: use tmux so the session survives SSH disconnection.
```bash
tmux new -s experiment
sudo bash ~/sdn-thesis/harness/scripts/batch_run.sh FULL 1 30
# Ctrl-B then D to detach; tmux attach -t experiment to reattach
```

Estimated time: 30 x (150 + 90 + 45 + 5) s ≈ 2.6 hours.

## Step 4 — Run ablation modes

```bash
# After FULL completes, run the other 3 modes (adds ~7.8 hours)
sudo bash ~/sdn-thesis/harness/scripts/ablation_run.sh 30 1
# The script runs NO_MULTI_WINDOW, NO_DUAL_MECH, FIXED_THRESHOLD
# (FULL already done above; set start_mode_idx=1 to skip it)
```

Or run all four including FULL:
```bash
sudo bash ~/sdn-thesis/harness/scripts/ablation_run.sh 30 0
```

## Step 5 — Compute metrics

```bash
python3 ~/sdn-thesis/harness/analysis/compute_metrics.py ~/sdn-thesis/logs/
```

Output:
- Console table with DR ± SD, FPR ± SD, proc_time ± SD per mode/window
- `logs/metrics_summary.csv`  — import into Excel for thesis tables
- `logs/per_run_metrics.csv`  — use for box plots / scatter in Chapter 4

## Environment variables for run_one_chunk.sh

| Variable         | Default   | Purpose                                   |
|------------------|-----------|-------------------------------------------|
| CALIBRATION_SECS | 150       | Duration of baseline calibration phase    |
| ATTACK_SECS      | 90        | Expected attack duration (+ margin)       |
| ATTACK_IFACE     | s5-eth7   | Interface tcpreplay sends attack packets  |

Set these before calling the script if needed:
```bash
ATTACK_IFACE=s5-eth9 sudo bash run_one_chunk.sh 1 FULL
```

## Ablation mode quick reference

| Mode             | Windows        | Alert condition          | Threshold  |
|------------------|----------------|--------------------------|------------|
| FULL             | 5s + 30s + 120s | M1 AND M2               | OAKF       |
| NO_MULTI_WINDOW  | 5s only         | M1 AND M2               | OAKF       |
| NO_DUAL_MECH     | 5s + 30s + 120s | M1 only (no M2)         | OAKF       |
| FIXED_THRESHOLD  | 5s + 30s + 120s | M1 AND M2               | Fixed (frozen at calibration end) |
