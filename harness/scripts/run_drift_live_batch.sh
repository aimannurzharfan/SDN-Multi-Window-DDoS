#!/bin/bash
# Phase 2 live drift batch: 5 runs, sequential, isolated. errexit off so a stray
# non-zero (e.g. mn --clean) never aborts the batch.
set +e
cd /home/sdnuser/sdn-thesis
LOG=logs/boun/drift_live/batch_driver.log
echo "=== DRIFT LIVE BATCH start $(date +%T) ===" > "$LOG"
for i in 1 2 3 4 5; do
  echo "--- run drift_j$i start $(date +%T) ---" >> "$LOG"
  mn --clean >/dev/null 2>&1
  python3 harness/scripts/experiment_drift_live.py "drift_j$i" >> "$LOG" 2>&1
  echo "--- run drift_j$i done  $(date +%T) exit=$? ---" >> "$LOG"
done
mn --clean >/dev/null 2>&1
echo "=== DRIFT LIVE BATCH complete $(date +%T) ===" >> "$LOG"
