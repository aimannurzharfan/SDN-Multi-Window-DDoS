#!/usr/bin/env bash
# =============================================================================
# batch_run.sh  —  Run all 30 experimental trials for a single ablation mode
#
# Usage:
#   sudo ./batch_run.sh [ABLATION_MODE] [start_chunk] [end_chunk]
#
#   ABLATION_MODE : FULL (default) | NO_MULTI_WINDOW | NO_DUAL_MECH |
#                   FIXED_THRESHOLD
#   start_chunk   : first chunk to run (default: 1)
#   end_chunk     : last chunk to run  (default: 30)
#
# Each chunk gets RUN_ID = "FULL_001" etc. so CSVs are uniquely named.
# =============================================================================

set -euo pipefail

ABLATION_MODE="${1:-FULL}"
START_CHUNK="${2:-0}"
END_CHUNK="${3:-29}"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_SCRIPT="${SCRIPTS_DIR}/run_one_chunk.sh"

if [[ ! -x "${RUN_SCRIPT}" ]]; then
    echo "[ERROR] run_one_chunk.sh not found or not executable at ${RUN_SCRIPT}"
    exit 1
fi

ts() { date "+%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*"; }

LOG_DIR="${HOME}/sdn-thesis/logs"
BATCH_LOG="${LOG_DIR}/batch_${ABLATION_MODE}_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "${LOG_DIR}"

log "=== BATCH RUN START: mode=${ABLATION_MODE} chunks ${START_CHUNK}-${END_CHUNK} ==="
log "Log: ${BATCH_LOG}"

FAILED_CHUNKS=()

for CHUNK in $(seq "${START_CHUNK}" "${END_CHUNK}"); do
    CHUNK_PAD=$(printf "%05d" "${CHUNK}")
    RUN_ID="${ABLATION_MODE}_${CHUNK_PAD}"
    log "--- Chunk ${CHUNK}/${END_CHUNK} (run_id=${RUN_ID}) ---"

    if sudo bash "${RUN_SCRIPT}" "${CHUNK}" "${ABLATION_MODE}" "${RUN_ID}" \
            2>&1 | tee -a "${BATCH_LOG}"; then
        log "Chunk ${CHUNK}: OK"
    else
        log "Chunk ${CHUNK}: FAILED (exit $?)"
        FAILED_CHUNKS+=("${CHUNK}")
    fi

    # Brief inter-trial pause to let OVS/Ryu fully tear down
    sleep 5
done

log "=== BATCH RUN COMPLETE ==="
if [[ ${#FAILED_CHUNKS[@]} -gt 0 ]]; then
    log "FAILED chunks: ${FAILED_CHUNKS[*]}"
    log "Re-run: sudo ./batch_run.sh ${ABLATION_MODE} <chunk> <chunk>"
    exit 1
else
    log "All chunks succeeded."
fi
