#!/usr/bin/env bash
# run_long_test.sh — run FULL mode against the 5-chunk long attack pcap and
# validate the 120s window produces attack-phase rows.
#
# Usage:  sudo -E bash ~/sdn-thesis/run_long_test.sh
# After it exits, run:  python3 ~/sdn-thesis/analyze_long_test.py

set -euo pipefail

THESIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP="${THESIS_DIR}/chunks/long_attack_5chunk.pcap"
LOG_DIR="${LOG_DIR:-${THESIS_DIR}/logs}"
RUN_ID="long_5chunk"
MODE="FULL"
CHUNK_ID=99   # placeholder; pcap path is overridden by SDN_ATTACK_PCAP
CSV="${LOG_DIR}/run_${RUN_ID}_chunk_${CHUNK_ID}_${MODE}.csv"

# ── pre-flight ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo -E bash $0)"; exit 1
fi
if [[ ! -f "${PCAP}" ]]; then
    echo "ERROR: long attack pcap not found: ${PCAP}"; exit 1
fi

PKT_COUNT=$(capinfos -c "${PCAP}" 2>/dev/null | grep -oP '\d[\d,]+' | tr -d ',' | head -1)
echo "========================================================"
echo "  Long-attack test: FULL mode"
echo "  PCAP : ${PCAP}"
echo "  Pkts : ${PKT_COUNT}  (~$((${PKT_COUNT:-0} / 5000))s at 5000 pps)"
echo "  CSV  : ${CSV}"
echo "========================================================"

# Remove any stale CSV from a previous run so validation is clean.
rm -f "${CSV}"

# ── run experiment ────────────────────────────────────────────────────────────
# Timing rationale:
#   CALIBRATION_SECS=150  — same as all other trials
#   ATTACK_SECS=440       — 419s replay + 21s margin; detector labels
#                           [calib_end, calib_end+445s) as "attack"
#   POST_ATTACK_SECS=130  — keeps Ryu alive past the last 120s window cycle
#                           (fires at t≈720s from Ryu start, after replay ends)
export CALIBRATION_SECS=150
export ATTACK_SECS=440
export POST_ATTACK_SECS=130
export SDN_ATTACK_PCAP="${PCAP}"
export LOG_DIR="${LOG_DIR}"

python3 "${THESIS_DIR}/harness/scripts/experiment.py" ${CHUNK_ID} ${MODE} ${RUN_ID}
EXIT_CODE=$?

# ── validate ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  Validation"
echo "========================================================"

PASS=1

# 1. Did the process exit cleanly?
if [[ ${EXIT_CODE} -ne 0 ]]; then
    echo "  FAIL: experiment.py exited with code ${EXIT_CODE}"
    PASS=0
fi

# 2. CSV exists and is non-empty?
if [[ ! -s "${CSV}" ]]; then
    echo "  FAIL: CSV not found or empty: ${CSV}"
    PASS=0
else
    ROWS=$(wc -l < "${CSV}")
    echo "  CSV rows (incl header): ${ROWS}"
fi

# 3. CSV contains calibration rows?
if [[ -s "${CSV}" ]]; then
    CAL_ROWS=$(grep -c ',calibration,' "${CSV}" 2>/dev/null || echo 0)
    if [[ "${CAL_ROWS}" -eq 0 ]]; then
        echo "  FAIL: no calibration-phase rows in CSV"
        PASS=0
    else
        echo "  Calibration rows : ${CAL_ROWS}"
    fi
fi

# 4. CSV contains attack rows in the 120s window?
if [[ -s "${CSV}" ]]; then
    ATK_120=$(grep ',attack,' "${CSV}" 2>/dev/null | grep -c ',120s,' || echo 0)
    if [[ "${ATK_120}" -eq 0 ]]; then
        echo "  FAIL: zero attack-phase rows for 120s window"
        PASS=0
    else
        echo "  120s attack rows : ${ATK_120}  (expect >= 3)"
    fi
fi

echo "========================================================"
if [[ ${PASS} -eq 1 ]]; then
    echo "  RESULT: PASS"
    echo "  Run analysis:  python3 ${THESIS_DIR}/analyze_long_test.py"
else
    echo "  RESULT: FAIL  (see messages above)"
fi
echo "========================================================"
