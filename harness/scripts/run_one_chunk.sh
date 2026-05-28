#!/usr/bin/env bash
# run_one_chunk.sh  —  thin wrapper around experiment.py
#
# Usage:
#   sudo bash run_one_chunk.sh <chunk_id> [ABLATION_MODE] [run_id]
#
# Examples:
#   sudo bash run_one_chunk.sh 1               # FULL mode, run_id=FULL_001
#   sudo bash run_one_chunk.sh 1 NO_DUAL_MECH  # ablation
#   sudo bash run_one_chunk.sh 1 FULL test01   # custom run_id for smoke test

set -euo pipefail

CHUNK_ID="${1:?Usage: sudo bash run_one_chunk.sh <chunk_id> [MODE] [run_id]}"
ABLATION_MODE="${2:-FULL}"
RUN_ID="${3:-}"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPERIMENT_PY="${SCRIPTS_DIR}/experiment.py"

# Activate Ryu virtualenv so ryu-manager is on PATH
RYU_VENV="${RYU_VENV:-${HOME}/ryu-env}"
if [[ -f "${RYU_VENV}/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "${RYU_VENV}/bin/activate"
else
    echo "[WARN] Ryu venv not found at ${RYU_VENV}. Trying system ryu-manager."
fi

# Build run_id if not supplied
if [[ -z "${RUN_ID}" ]]; then
    RUN_ID="${ABLATION_MODE}_$(printf '%03d' "${CHUNK_ID}")"
fi

exec sudo -E python3 "${EXPERIMENT_PY}" "${CHUNK_ID}" "${ABLATION_MODE}" "${RUN_ID}"
