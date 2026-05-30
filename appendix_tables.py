#!/usr/bin/env python3
"""Appendix B results tables from experiment CSV logs."""
import os, sys, glob
import pandas as pd

LOGS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/sdn-thesis/logs")
OUT  = os.path.join(LOGS, "appendix_B.md")

NAMES = ["timestamp","elapsed_s","phase","window","packets","unique_ips","syn",
    "synack","entropy","entropy_thresh","entropy_anom","revisit","revisit_thresh",
    "revisit_anom","synack_ratio","synack_thresh","synack_anom","mech1","mech2",
    "alert","proc_time_ms","run_id","chunk_id","ablation_mode"]
MODES = ["FULL","NO_MULTI_WINDOW","NO_DUAL_MECH","FIXED_THRESHOLD"]
MODE_LABEL = {
    "FULL":             "Full System",
    "NO_MULTI_WINDOW":  "No Multi-Window",
    "NO_DUAL_MECH":     "No Dual-Mech",
    "FIXED_THRESHOLD":  "Fixed Threshold",
}

# ---------------------------------------------------------------------------
# Data loading — identical to make_thesis_figures.py
# ---------------------------------------------------------------------------
def load():
    fr = []
    for f in glob.glob(os.path.join(LOGS, "*.csv")):
        b = os.path.basename(f).lower()
        try:
            d = pd.read_csv(f, header=0, names=NAMES, usecols=range(24))
        except Exception as e:
            print(f"  skip {b}: {e}", file=sys.stderr)
            continue
        d["__rerun"] = "rerun" in b
        fr.append(d)
    if not fr:
        sys.exit(f"No CSVs found in {LOGS}")
    df = pd.concat(fr, ignore_index=True)
    df["chunk_id"] = pd.to_numeric(df["chunk_id"], errors="coerce")
    for c in ["alert", "entropy", "entropy_thresh", "synack_ratio",
              "synack_thresh", "elapsed_s"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["alert"] = df["alert"].fillna(0).astype(int)
    return df

ABLATION_CHUNKS = set(range(30))   # chunks 0-29 are the 30-trial ablation study

def dedup_mode(df, mode):
    rows = df[(df["ablation_mode"] == mode) &
              (df["chunk_id"].isin(ABLATION_CHUNKS))].copy()
    rr   = set(rows.loc[rows["__rerun"], "chunk_id"].dropna().unique())
    return rows[~((rows["chunk_id"].isin(rr)) & (~rows["__rerun"]))]

def dedup_full(df):
    return dedup_mode(df, "FULL")

def mode_rows(df, m):
    return dedup_mode(df, m)

# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------
def chunk_dr(rows, win="5s"):
    """Return Series indexed by chunk_id with DR% for attack cycles."""
    w = rows[(rows["window"] == win) & (rows["phase"] == "attack")]
    g = w.groupby("chunk_id")["alert"].agg(["sum", "count"])
    return g["sum"], g["count"]          # det, att per chunk

def pooled_dr(rows, win="5s"):
    w  = rows[(rows["window"] == win) & (rows["phase"] == "attack")]
    det = int(w["alert"].sum())
    att = len(w)
    return det, att

def pooled_fpr(rows, win="5s"):
    w   = rows[(rows["window"] == win) & (rows["phase"] == "calibration")]
    fp  = int(w["alert"].sum())
    cal = len(w)
    return fp, cal

def cell(det, att):
    pct = 100.0 * det / att if att else float("nan")
    return f"{det}/{att} ({pct:.1f}%)"

# ---------------------------------------------------------------------------
# Table B1 — per-chunk DR, 5s window
# ---------------------------------------------------------------------------
def table_b1(df):
    chunks = list(range(30))
    # Pre-compute (det, att) per chunk per mode
    data = {}
    for m in MODES:
        det_s, att_s = chunk_dr(mode_rows(df, m), "5s")
        data[m] = (det_s, att_s)

    header = "| Chunk | " + " | ".join(MODE_LABEL[m] for m in MODES) + " |"
    sep    = "|------:|" + "|".join([":---------:"] * len(MODES)) + "|"
    rows   = [header, sep]

    for ch in chunks:
        cells = []
        for m in MODES:
            det_s, att_s = data[m]
            if ch in det_s.index:
                cells.append(cell(int(det_s[ch]), int(att_s[ch])))
            else:
                cells.append("—")
        rows.append(f"| {ch:2d} | " + " | ".join(cells) + " |")

    # Footer: pooled DR per mode
    footer_cells = []
    for m in MODES:
        det, att = pooled_dr(mode_rows(df, m), "5s")
        footer_cells.append(cell(det, att))
    rows.append("| **Pooled** | " + " | ".join(f"**{c}**" for c in footer_cells) + " |")

    return "\n".join(rows)

# ---------------------------------------------------------------------------
# Table B2 — per-mode summary, 5s window
# ---------------------------------------------------------------------------
def table_b2(df):
    header = "| Mode | Pooled DR | Mean DR per chunk | Std Dev | FPR |"
    sep    = "|:-----|:---------:|:-----------------:|:-------:|:---:|"
    rows   = [header, sep]

    for m in MODES:
        r      = mode_rows(df, m)
        det, att = pooled_dr(r, "5s")
        fp,  cal = pooled_fpr(r, "5s")
        det_s, att_s = chunk_dr(r, "5s")
        pc_dr  = 100.0 * det_s / att_s       # per-chunk DR%
        mean   = pc_dr.mean()
        std    = pc_dr.std()
        pooled = f"{det}/{att} ({100*det/att:.1f}%)" if att else "—"
        fpr    = f"{fp}/{cal} ({100*fp/cal:.3f}%)"   if cal else "—"
        rows.append(
            f"| {MODE_LABEL[m]} | {pooled} | {mean:.1f}% | {std:.1f}% | {fpr} |"
        )

    return "\n".join(rows)

# ---------------------------------------------------------------------------
# Table B3 — FULL mode per observation window
# ---------------------------------------------------------------------------
def table_b3(df):
    full   = dedup_full(df)
    wins   = ["5s", "30s", "120s"]
    header = "| Window | DR (det/att) | DR% | FPR (fp/cal) | FPR% |"
    sep    = "|:------:|:-----------:|:---:|:------------:|:----:|"
    rows   = [header, sep]

    for w in wins:
        det, att = pooled_dr(full, w)
        fp,  cal = pooled_fpr(full, w)
        dr_pct   = 100.0 * det / att if att else float("nan")
        fpr_pct  = 100.0 * fp  / cal if cal else float("nan")
        rows.append(
            f"| {w} | {det}/{att} | {dr_pct:.1f}% | {fp}/{cal} | {fpr_pct:.3f}% |"
        )

    return "\n".join(rows)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(f"Loading CSVs from {LOGS} …", file=sys.stderr)
    df = load()
    print(f"  {len(df):,} rows loaded", file=sys.stderr)

    # Sanity check
    full        = dedup_full(df)
    det_full, att_full = pooled_dr(full, "5s")
    dr_full_pct = 100.0 * det_full / att_full if att_full else float("nan")
    print(f"  FULL mode 5s pooled DR: {det_full}/{att_full} = {dr_full_pct:.1f}%",
          file=sys.stderr)
    if abs(dr_full_pct - 95.5) > 0.15:
        print(f"  WARNING: expected ~95.5%, got {dr_full_pct:.1f}%", file=sys.stderr)

    b1 = table_b1(df)
    b2 = table_b2(df)
    b3 = table_b3(df)

    md = f"""# Appendix B — Experiment Results Tables

## Table B1 — Per-Chunk Detection Rate, 5 s Window

{b1}

## Table B2 — Per-Mode Summary, 5 s Window

{b2}

## Table B3 — FULL Mode Performance by Observation Window

{b3}
"""

    # Print to stdout
    print(md)

    # Save to file
    with open(OUT, "w") as fh:
        fh.write(md)
    print(f"Saved → {OUT}", file=sys.stderr)

    # Explicit sanity confirmation
    print(f"\nSanity check: FULL 5s pooled DR = {det_full}/{att_full} "
          f"({dr_full_pct:.1f}%) — "
          + ("PASS ✓" if abs(dr_full_pct - 95.5) <= 0.15 else "FAIL ✗"),
          file=sys.stderr)

if __name__ == "__main__":
    main()
