#!/usr/bin/env bash
# run_all.sh — batch runner: 30 chunks × 4 ablation modes = 120 trials.
#
# Usage:
#   sudo bash ~/sdn-thesis/run_all.sh
#
# Timing:  ~6 min/trial (150s calib + 70s overhead + 90s attack + 35s post)
#          120 trials ≈ 12 hours total.
#
# Outputs written by experiment.py for each trial:
#   logs/run_<run_id>_chunk_<chunk>_<MODE>.csv   — detector CSV
#   logs/ryu_<run_id>_chunk<chunk>_<MODE>.log    — Ryu controller log
#
# This script also writes:
#   logs/batch_progress.log   — trial-by-trial status + all trial stdout/stderr

set -uo pipefail

THESIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$THESIS_DIR/logs"
PROGRESS_LOG="$LOG_DIR/batch_progress.log"
EXPERIMENT="$THESIS_DIR/harness/scripts/experiment.py"

MODES=(FULL NO_MULTI_WINDOW NO_DUAL_MECH FIXED_THRESHOLD)

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [ ! -f "$EXPERIMENT" ]; then
    echo "[ERROR] experiment.py not found: $EXPERIMENT" >&2
    exit 1
fi

missing_chunks=0
for chunk in $(seq 0 29); do
    pcap="$THESIS_DIR/chunks/$(printf 'chunk_%05d.pcap' "$chunk")"
    if [ ! -f "$pcap" ]; then
        echo "[ERROR] Missing PCAP: $pcap" >&2
        missing_chunks=$((missing_chunks + 1))
    fi
done
if [ "$missing_chunks" -gt 0 ]; then
    echo "[ERROR] $missing_chunks chunk(s) missing. Aborting." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Batch run
# ---------------------------------------------------------------------------

trial=0
passed=0
failed=0
batch_start=$(date '+%Y-%m-%d %H:%M:%S')

{
    echo "========================================================"
    echo "  BATCH START:  $batch_start"
    echo "  Trials:       120  (chunks 0-29 x 4 ablation modes)"
    echo "  Order:        chunk-outer, mode-inner"
    echo "  Estimated:    ~12 hours"
    echo "  Progress log: $PROGRESS_LOG"
    echo "========================================================"
} | tee -a "$PROGRESS_LOG"

for chunk in $(seq 0 29); do
    for mode in "${MODES[@]}"; do
        trial=$((trial + 1))
        chunk_pad=$(printf "%02d" "$chunk")
        run_id="batch_${mode}_c${chunk_pad}"
        ts=$(date '+%Y-%m-%d %H:%M:%S')

        {
            echo ""
            echo "--------------------------------------------------------"
            echo "  Trial $trial/120 | $ts"
            echo "  chunk=$chunk  mode=$mode  run_id=$run_id"
            echo "--------------------------------------------------------"
        } | tee -a "$PROGRESS_LOG"

        if CALIBRATION_SECS=150 ATTACK_SECS=90 sudo -E python3 \
               "$EXPERIMENT" "$chunk" "$mode" "$run_id" \
               >> "$PROGRESS_LOG" 2>&1; then
            passed=$((passed + 1))
            result="PASSED"
        else
            exit_code=$?
            failed=$((failed + 1))
            result="FAILED (exit $exit_code)"
        fi

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Trial $trial $result: $run_id" \
            | tee -a "$PROGRESS_LOG"

        # Sleep between trials to let OVS flows expire and kernel state settle.
        # Skip the sleep after the final trial.
        if [ "$trial" -lt 120 ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sleeping 5s before next trial ..." \
                | tee -a "$PROGRESS_LOG"
            sleep 5
        fi
    done
done

{
    echo ""
    echo "========================================================"
    echo "  BATCH COMPLETE: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Started:  $batch_start"
    echo "  Passed:   $passed / 120"
    echo "  Failed:   $failed / 120"
    echo "========================================================"
} | tee -a "$PROGRESS_LOG"
