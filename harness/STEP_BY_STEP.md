# Step-by-Step: From Here to First Successful Test

Work through these one at a time. Don't skip ahead.

---

## STEP 1 — Push harness to GitHub (run on your Windows host)

Open a terminal in the `SDN Research Paper` folder (where this file is),
then run:

```bash
cd "C:\Users\aiman\Documents\Claude\Projects\SDN Research Paper"

# If the harness folder is not already a git repo, initialise it:
cd harness
git init
git remote add origin https://github.com/aimannurzharfan/sdn-multi-window-ddos.git
git fetch origin main
git checkout -b harness-branch
git add .
git commit -m "Add experiment harness (detector v2, experiment.py, scripts, analysis)"
git push origin harness-branch
```

Then on GitHub, merge harness-branch into main (or just push directly to main
if you prefer):
```bash
git push origin harness-branch:main --force
```

> Alternatively — since GitHub is integrated with Claude — you can ask Claude
> to commit and push directly in this session.

---

## STEP 2 — Fix Guest Additions (inside the Ubuntu VM)

Follow `GUEST_ADDITIONS_UPGRADE.md` exactly.

Verification:
```bash
ls /media/sf_SDNResearch/   # should list files from your Windows folder
# OR
ls ~/SDNResearch/
```

If it works, skip Step 3 (git pull). If it still doesn't work, go to Step 3.

---

## STEP 3 — Pull harness inside the VM

```bash
cd ~/sdn-thesis
git pull origin main
```

Then set up the directory layout experiment.py expects:
```bash
mkdir -p ~/sdn-thesis/harness
cp -r ~/sdn-thesis/detector   ~/sdn-thesis/harness/detector
# The new detector v2:
# harness/detector/multi_window_detector_v2.py  (from git)
# harness/detector/oakf.py                      (copy from existing)
cp ~/sdn-thesis/detector/oakf.py ~/sdn-thesis/harness/detector/
chmod +x ~/sdn-thesis/harness/scripts/*.sh
```

---

## STEP 4 — Verify environment

```bash
source ~/ryu-env/bin/activate
bash ~/sdn-thesis/scripts/check_environment.sh
```

Expected: Ryu, Mininet, OVS, tcpreplay all present. Chunks present.

---

## STEP 5 — Smoke test (single chunk, short run)

This is the most important step. Do it before any batch run.

```bash
source ~/ryu-env/bin/activate

# Quick smoke test: only 30 s calibration, uses chunk 1
CALIBRATION_SECS=30 ATTACK_SECS=30 \
  sudo -E python3 ~/sdn-thesis/harness/scripts/experiment.py 1 FULL smoke_test

# Watch the output — you should see:
#   [HH:MM:SS] Starting Ryu -> ...
#   [HH:MM:SS] Building Mininet topology ...
#   [HH:MM:SS] CALIBRATION START (30 s) ...
#   [HH:MM:SS] ATTACK START: tcpreplay ...
#   [HH:MM:SS] Attack injection done. Duration: XX.X s
#   [HH:MM:SS] === TRIAL COMPLETE ===
```

Then inspect the CSV:
```bash
CSV=~/sdn-thesis/logs/run_smoke_test_chunk_1_FULL.csv
head -3 "$CSV"
# Should show header + first row(s)
grep "attack" "$CSV" | head -5
# Should show rows with phase=attack and alert=1
grep "calibration" "$CSV" | head -5
# Should show rows with phase=calibration and alert=0
```

**What to tell me if something breaks:**
- If Ryu dies: `cat ~/sdn-thesis/logs/ryu_smoke_test_*.log | tail -30`
- If Mininet dies: check terminal output
- If CSV is empty or all calibration: means tcpreplay failed; check
  `cat ~/sdn-thesis/logs/tcpreplay_chunk001.log`

---

## STEP 6 — Full 30-chunk run (after smoke test passes)

Use tmux so the session survives if your terminal disconnects:
```bash
tmux new -s experiment
source ~/ryu-env/bin/activate
sudo bash ~/sdn-thesis/harness/scripts/batch_run.sh FULL 1 30
# Detach: Ctrl-B then D
# Reattach: tmux attach -t experiment
```

Estimated time: 30 × (12 + 15 + 150 + 84 + 35 + 5) ≈ **2.6 hours**

---

## STEP 7 — Compute metrics

```bash
python3 ~/sdn-thesis/harness/analysis/compute_metrics.py ~/sdn-thesis/logs/
```

Copy the console output to me and I'll write Chapter 4.

---

## STEP 8 — Ablation runs (after FULL results look good)

```bash
tmux new -s ablation
source ~/ryu-env/bin/activate
# Runs NO_MULTI_WINDOW, NO_DUAL_MECH, FIXED_THRESHOLD (skip mode index 0 = FULL)
sudo bash ~/sdn-thesis/harness/scripts/ablation_run.sh 30 1
```

Estimated time: **3 × 2.6 hours ≈ 8 hours**

---

## Troubleshooting quick reference

| Symptom | Where to look | Likely cause |
|---------|--------------|-------------|
| Ryu exits immediately | `ryu_*.log` | Wrong Python path, oakf.py not in PYTHONPATH |
| No attack-phase rows in CSV | `tcpreplay_*.log` | Wrong chunk path, interface name issue |
| All alerts = 0 during attack | Ryu log | OAKF still in warmup, or chunk too short |
| mn --clean hangs | Kill manually: `sudo ovs-vsctl del-br <br>` | OVS leftover state |
| iperf3 not found | `sudo apt install iperf3` | Missing package |
