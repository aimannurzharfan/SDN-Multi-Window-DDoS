#!/usr/bin/env python3
"""Analyze the long-attack (5-chunk) test CSV.

Reports DR (det/att) and FPR (fp/cal) for the 5s, 30s, and 120s windows,
confirming the 120s window is > 0% now that the attack outlasts the window.
"""
import os, sys, glob
import pandas as pd

LOGS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/sdn-thesis/logs")

NAMES = ["timestamp","elapsed_s","phase","window","packets","unique_ips","syn",
    "synack","entropy","entropy_thresh","entropy_anom","revisit","revisit_thresh",
    "revisit_anom","synack_ratio","synack_thresh","synack_anom","mech1","mech2",
    "alert","proc_time_ms","run_id","chunk_id","ablation_mode"]

# Find the long-test CSV
candidates = glob.glob(os.path.join(LOGS, "run_long_5chunk_chunk_99_FULL.csv"))
if not candidates:
    sys.exit(f"ERROR: long-test CSV not found in {LOGS}\n"
             "  Expected: run_long_5chunk_chunk_99_FULL.csv")

csv_path = candidates[0]
print(f"Loading: {csv_path}")

df = pd.read_csv(csv_path, header=0, names=NAMES, usecols=range(24),
                 encoding="utf-8", on_bad_lines="skip")
for c in ["elapsed_s", "alert"]:
    df[c] = pd.to_numeric(df[c], errors="coerce")
df["alert"] = df["alert"].fillna(0).astype(int)

print(f"Rows loaded: {len(df):,}")
print(f"Phase distribution:\n{df.groupby(['window','phase']).size().to_string()}\n")

WINDOWS = ["5s", "30s", "120s"]

print("=" * 60)
print("Detection Rate and FPR by observation window (FULL mode)")
print("=" * 60)
print(f"  {'Window':>8}  {'DR (det/att)':>18}  {'DR%':>7}  {'FPR (fp/cal)':>18}  {'FPR%':>8}")
print(f"  {'------':>8}  {'------------':>18}  {'---':>7}  {'------------':>18}  {'----':>8}")

for win in WINDOWS:
    wdf = df[df["window"] == win]
    atk = wdf[wdf["phase"] == "attack"]
    cal = wdf[wdf["phase"] == "calibration"]
    det = int(atk["alert"].sum())
    att = len(atk)
    fp  = int(cal["alert"].sum())
    nc  = len(cal)
    dr_pct  = 100.0 * det / att if att else float("nan")
    fpr_pct = 100.0 * fp  / nc  if nc  else float("nan")
    flag = ""
    if win == "120s" and att > 0 and det > 0:
        flag = "  ← 120s DR > 0 ✓"
    elif win == "120s" and att == 0:
        flag = "  ← WARNING: no attack cycles"
    print(f"  {win:>8}  {det:>6}/{att:<10}  {dr_pct:>6.1f}%  "
          f"{fp:>5}/{nc:<11}  {fpr_pct:>7.3f}%{flag}")

print()

# Detailed 120s window attack cycles
atk_120 = df[(df["window"] == "120s") & (df["phase"] == "attack")].copy()
if len(atk_120):
    print("120s window — attack-phase cycles:")
    cols = ["elapsed_s","entropy","entropy_thresh","entropy_anom",
            "synack_ratio","synack_thresh","synack_anom","mech1","mech2","alert"]
    print(atk_120[cols].to_string(index=False))
else:
    print("WARNING: no 120s attack-phase cycles found.")

print()
print("=" * 60)
if len(atk_120) >= 3 and atk_120["alert"].sum() > 0:
    print("CONCLUSION: 120s window detects sustained attack — PASS")
elif len(atk_120) > 0:
    print(f"CONCLUSION: 120s window has {len(atk_120)} cycle(s), "
          f"{atk_120['alert'].sum()} detection(s)")
else:
    print("CONCLUSION: FAIL — no 120s attack cycles recorded")
print("=" * 60)
