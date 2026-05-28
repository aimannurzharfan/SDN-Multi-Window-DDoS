#!/usr/bin/env bash
# =============================================================================
# ablation_run.sh  —  Run all four ablation modes across all chunks
#
# Usage:
#   sudo ./ablation_run.sh [num_chunks] [start_mode_idx]
#
#   num_chunks     : how many chunks per mode (default: 30)
#   start_mode_idx : 0-3, resume from this mode index (default: 0)
#
# Mode order:
#   0 = FULL              (proposed system, run first as the main result)
#   1 = NO_MULTI_WINDOW   (single-window baseline)
#   2 = NO_DUAL_MECH      (no SYN/ACK confirmation)
#   3 = FIXED_THRESHOLD   (no OAKF adaptation)
#
# This takes approximately 4 x 30 x (150 + 90 + 45) s ≈ 34 hours.
# Run in a tmux session: tmux new -s ablation
# =============================================================================

set -euo pipefail

NUM_CHUNKS="${1:-30}"
START_IDX="${2:-0}"

MODES=(FULL NO_MULTI_WINDOW NO_DUAL_MECH FIXED_THRESHOLD)
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
BATCH_SCRIPT="${SCRIPTS_DIR}/batch_run.sh"

ts() { date "+%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*"; }

log "=== ABLATION SUITE: ${#MODES[@]} modes x ${NUM_CHUNKS} chunks ==="

for IDX in "${!MODES[@]}"; do
    if [[ "${IDX}" -lt "${START_IDX}" ]]; then
        log "Skipping mode[${IDX}]=${MODES[$IDX]} (resume from idx ${START_IDX})"
        continue
    fi

    MODE="${MODES[$IDX]}"
    log ">>> MODE ${IDX}/${#MODES[@]}: ${MODE}"
    sudo bash "${BATCH_SCRIPT}" "${MODE}" 1 "${NUM_CHUNKS}"
    log "<<< MODE ${MODE} complete"
    sleep 10
done

log "=== ABLATION SUITE COMPLETE ==="
log "Run analysis: python3 ~/sdn-thesis/harness/analysis/compute_metrics.py"
