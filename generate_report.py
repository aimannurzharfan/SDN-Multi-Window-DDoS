#!/usr/bin/env python3
"""
generate_report.py — HTML report from experiment CSVs.

Reads all run_*.csv files from ~/sdn-thesis/logs/ and produces:
  - ~/sdn-thesis/logs/report.html            (main summary report)
  - ~/sdn-thesis/logs/report_chunk_<NN>.html (one per chunk with data)

Usage:
    python3 ~/sdn-thesis/generate_report.py [logs_dir]

    logs_dir: optional path override (default: ~/sdn-thesis/logs)

Main report sections:
    1. Top stat bar          — DR / FPR / proc_time for FULL mode, 5s window
    2. Mode comparison table — all 4 ablation modes, 5s window
    3. Window breakdown      — FULL mode, all three window sizes
    4. Per-chunk DR grid     — FULL mode, 5s window, colour-coded
    5. File inventory        — list of CSVs read

Per-chunk report sections:
    1. Mode comparison table — DR / FPR / proc for all 4 modes, 5s window
    2. Window breakdown      — FULL mode, 5s / 30s / 120s
    3. Signal trace          — every 5s cycle (FULL mode): elapsed, phase,
                               syn, synack, entropy, revisit, synack_ratio, alert

Standard library only (csv, glob, math, os, sys).
"""

import csv
import glob
import math
import os
import sys
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOGS_DIR = (os.path.expanduser(sys.argv[1]) if len(sys.argv) > 1
            else os.path.expanduser("~/sdn-thesis/logs"))
OUTPUT_PATH = os.path.join(LOGS_DIR, "report.html")

MODES   = ["FULL", "NO_MULTI_WINDOW", "NO_DUAL_MECH", "FIXED_THRESHOLD"]
WINDOWS = ["5s", "30s", "120s"]

# Target thresholds from thesis specification
TARGET_DR  = 0.95    # ≥ 95 %
TARGET_FPR = 0.0097  # < 0.97 %


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

class RunResult:
    """Holds all cycle rows for one CSV (one run × one chunk × one mode)."""

    def __init__(self, run_id: str, chunk_id: str, mode: str):
        self.run_id   = run_id
        self.chunk_id = int(chunk_id)
        self.mode     = mode
        self.cycles: dict = defaultdict(list)   # window -> [row_dict, ...]

    def add(self, window: str, row: dict):
        self.cycles[window].append(row)

    def _rows(self, window: str, phase: str) -> list:
        return [r for r in self.cycles.get(window, [])
                if r.get("phase", "") == phase]

    def dr(self, window: str):
        rows = self._rows(window, "attack")
        if not rows:
            return None
        return sum(1 for r in rows if r.get("alert") == "1") / len(rows)

    def fpr(self, window: str):
        rows = self._rows(window, "calibration")
        if not rows:
            return None
        return sum(1 for r in rows if r.get("alert") == "1") / len(rows)

    def proc(self, window: str):
        rows = self.cycles.get(window, [])
        if not rows:
            return None
        return sum(float(r["proc_time_ms"]) for r in rows) / len(rows)

    def attack_n(self, window: str) -> int:
        return len(self._rows(window, "attack"))

    def calib_n(self, window: str) -> int:
        return len(self._rows(window, "calibration"))


def load_runs(logs_dir: str) -> list:
    """Return list of (filepath, RunResult) for every run_*.csv in logs_dir."""
    pattern = os.path.join(logs_dir, "run_*.csv")
    runs = []
    for fpath in sorted(glob.glob(pattern)):
        try:
            with open(fpath, newline="") as fh:
                reader = csv.DictReader(fh)
                run = None
                for row in reader:
                    if run is None:
                        run = RunResult(
                            row.get("run_id", "?"),
                            row.get("chunk_id", "0"),
                            row.get("ablation_mode", "FULL"),
                        )
                    w = row.get("window", "").strip()
                    if w:
                        run.add(w, row)
                if run is not None:
                    runs.append((fpath, run))
        except Exception as exc:
            print(f"[WARN] skipping {os.path.basename(fpath)}: {exc}",
                  file=sys.stderr)
    return runs


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _clean(vals: list) -> list:
    return [v for v in vals if v is not None]

def _mean(vals: list):
    v = _clean(vals)
    return sum(v) / len(v) if v else None

def _stdev(vals: list) -> float:
    v = _clean(vals)
    if len(v) < 2:
        return 0.0
    m = sum(v) / len(v)
    return math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1))


def pct(v, decimals: int = 1) -> str:
    return f"{v * 100:.{decimals}f}%" if v is not None else "—"

def pct_pm(v, sd, decimals: int = 1) -> str:
    if v is None:
        return "—"
    if sd == 0.0:
        return f"{v * 100:.{decimals}f}%"
    return f"{v * 100:.{decimals}f}% ± {sd * 100:.{decimals}f}%"

def ms_fmt(v) -> str:
    return f"{v:.3f} ms" if v is not None else "—"


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate(runs: list) -> dict:
    """Return {mode: {window: {dr:[], fpr:[], proc:[]}}}."""
    agg = {m: {w: {"dr": [], "fpr": [], "proc": []}
               for w in WINDOWS}
           for m in MODES}
    for _, run in runs:
        if run.mode not in agg:
            continue
        for w in WINDOWS:
            for key, val in [("dr", run.dr(w)),
                             ("fpr", run.fpr(w)),
                             ("proc", run.proc(w))]:
                if val is not None:
                    agg[run.mode][w][key].append(val)
    return agg


def chunk_dr_map(runs: list) -> dict:
    """Return {chunk_id: dr_or_None} for FULL mode, 5s window.
    Multiple runs for the same chunk are averaged."""
    by_chunk: dict = defaultdict(list)
    for _, run in runs:
        if run.mode == "FULL":
            dr = run.dr("5s")
            if dr is not None:
                by_chunk[run.chunk_id].append(dr)
    return {cid: (_mean(vals) if vals else None)
            for cid, vals in by_chunk.items()}


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _dr_colors(dr) -> tuple:
    """Return (bg, fg) hex strings for a DR value."""
    if dr is None:
        return "#21262d", "#6e7681"
    if dr >= 0.99:
        return "#0f2a14", "#3fb950"
    if dr >= 0.95:
        return "#2d2208", "#d29922"
    if dr >= 0.80:
        return "#2d1608", "#db6d28"
    return "#2d0c0a", "#f85149"


def _badge(dr_m, fpr_m, n: int) -> str:
    """PASS / WARN / FAIL / — tag."""
    if n == 0 or dr_m is None or fpr_m is None:
        return '<span class="tag">—</span>'
    if dr_m >= TARGET_DR and fpr_m < TARGET_FPR:
        return '<span class="tag tag-pass">PASS</span>'
    if dr_m >= 0.80:
        return '<span class="tag tag-warn">WARN</span>'
    return '<span class="tag tag-fail">FAIL</span>'


def _stat_cls_dr(v) -> str:
    if v is None:
        return "stat-muted"
    return "stat-pass" if v >= TARGET_DR else ("stat-warn" if v >= 0.80 else "stat-fail")

def _stat_cls_fpr(v) -> str:
    if v is None:
        return "stat-muted"
    return "stat-pass" if v < TARGET_FPR else "stat-fail"


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CSS = """
:root {
    --bg:      #0d1117;
    --surf:    #161b22;
    --surf2:   #21262d;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --yellow:  #d29922;
    --orange:  #db6d28;
    --red:     #f85149;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: ui-monospace, "Cascadia Code", "Fira Code",
                 "JetBrains Mono", monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 40px 32px;
    max-width: 1100px;
    margin: 0 auto;
}
header { margin-bottom: 36px; }
header h1 {
    font-size: 20px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.02em;
    margin-bottom: 4px;
}
header p { color: var(--muted); font-size: 11px; }

h2 {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin: 36px 0 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
}

/* ---- Stat bar ---- */
.stat-bar { display: flex; gap: 12px; flex-wrap: wrap; }
.stat-card {
    background: var(--surf);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 22px;
    flex: 1;
    min-width: 150px;
}
.stat-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--muted);
    margin-bottom: 8px;
}
.stat-value { font-size: 28px; font-weight: 700; letter-spacing: -0.03em; }
.stat-sub   { font-size: 10px; color: var(--muted); margin-top: 4px; }
.stat-pass  { color: var(--green); }
.stat-warn  { color: var(--yellow); }
.stat-fail  { color: var(--red); }
.stat-muted { color: var(--muted); }

/* ---- Tables ---- */
.table-wrap { overflow-x: auto; }
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--surf);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    font-size: 12px;
}
thead th {
    background: var(--surf2);
    padding: 9px 14px;
    text-align: left;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
}
td {
    padding: 9px 14px;
    border-bottom: 1px solid var(--border);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--surf2); }
td.r { text-align: right; }
td.mode-col { color: var(--accent); font-weight: 600; }
.em   { color: var(--text); font-weight: 500; }
.dim  { color: var(--muted); }

/* ---- Badges ---- */
.tag {
    display: inline-block;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 8px;
    font-size: 10px;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.04em;
}
.tag-pass { border-color: var(--green);  color: var(--green); }
.tag-warn { border-color: var(--yellow); color: var(--yellow); }
.tag-fail { border-color: var(--red);    color: var(--red); }

/* ---- DR grid ---- */
.dr-grid {
    display: grid;
    grid-template-columns: repeat(10, 1fr);
    gap: 5px;
    margin-bottom: 12px;
}
.dr-cell {
    border-radius: 6px;
    padding: 9px 4px 7px;
    text-align: center;
    font-size: 12px;
    font-weight: 700;
    line-height: 1.3;
}
.dr-cell-id {
    font-size: 9px;
    font-weight: 400;
    opacity: 0.7;
    margin-bottom: 2px;
}
.legend {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    font-size: 10px;
    align-items: center;
    color: var(--muted);
}
.legend-chip {
    border-radius: 4px;
    padding: 2px 10px;
    font-weight: 600;
}

/* ---- File list ---- */
.file-list {
    background: var(--surf);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    font-size: 11px;
    color: var(--muted);
    line-height: 2;
}
.file-list .fname { color: var(--text); }
.file-list .fsize { color: var(--border); }

.no-data {
    display: block;
    padding: 28px;
    text-align: center;
    color: var(--muted);
    font-style: italic;
    background: var(--surf);
    border: 1px solid var(--border);
    border-radius: 8px;
}

/* ---- Per-chunk signal trace ---- */
.phase-cal  { color: var(--muted); }
.phase-att  { color: var(--orange); font-weight: 600; }
.phase-post { color: var(--border); }
.alert-yes  { color: var(--green); font-weight: 700; }
.alert-no   { color: var(--border); }

/* ---- Back-nav link ---- */
.nav-back {
    display: inline-block;
    margin-bottom: 24px;
    font-size: 11px;
    color: var(--accent);
    text-decoration: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 12px;
}
.nav-back:hover { background: var(--surf2); }
"""


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_html(runs: list, agg: dict, chunk_grid: dict) -> str:
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n_csvs = len(runs)
    files  = [fp for fp, _ in runs]

    p: list = []
    w = p.append

    # ---- Head ----
    w(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SDN Thesis — Results</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Multi-Window TCP SYN Flood Detector — Results Report</h1>
  <p>Generated {now} &nbsp;|&nbsp; {n_csvs} CSV(s) loaded &nbsp;|&nbsp;
     Targets: DR ≥ {TARGET_DR*100:.0f}%,  FPR &lt; {TARGET_FPR*100:.2f}%</p>
</header>
""")

    # ================================================================== #
    # Section 1: Stat bar — FULL / 5s                                    #
    # ================================================================== #
    w('<h2>Primary metrics — FULL mode · 5 s window</h2>\n')

    d5   = agg.get("FULL", {}).get("5s", {})
    dr_v = d5.get("dr",   [])
    fp_v = d5.get("fpr",  [])
    pr_v = d5.get("proc", [])
    n5   = len(dr_v)

    dr_m   = _mean(dr_v)
    fpr_m  = _mean(fp_v)
    proc_m = _mean(pr_v)

    w('<div class="stat-bar">\n')

    if n5 == 0:
        w('<span class="no-data">No FULL-mode runs with attack cycles found.</span>\n')
    else:
        # DR stat card
        dr_cls = _stat_cls_dr(dr_m)
        w(f"""<div class="stat-card">
  <div class="stat-label">Detection Rate (DR)</div>
  <div class="stat-value {dr_cls}">{pct(dr_m, 1)}</div>
  <div class="stat-sub">target ≥ {TARGET_DR*100:.0f}% &nbsp;|&nbsp; SD {pct(_stdev(dr_v), 1)} over {n5} run(s)</div>
</div>
""")

        # FPR stat card
        fpr_cls = _stat_cls_fpr(fpr_m)
        w(f"""<div class="stat-card">
  <div class="stat-label">False Positive Rate (FPR)</div>
  <div class="stat-value {fpr_cls}">{pct(fpr_m, 3)}</div>
  <div class="stat-sub">target &lt; {TARGET_FPR*100:.2f}% &nbsp;|&nbsp; SD {pct(_stdev(fp_v), 3)}</div>
</div>
""")

        # Proc time
        w(f"""<div class="stat-card">
  <div class="stat-label">Mean Proc Time</div>
  <div class="stat-value">{ms_fmt(proc_m)}</div>
  <div class="stat-sub">per 5 s window cycle</div>
</div>
""")

        # Run count
        w(f"""<div class="stat-card">
  <div class="stat-label">Runs Loaded</div>
  <div class="stat-value">{n5}</div>
  <div class="stat-sub">FULL mode with attack data</div>
</div>
""")

    w('</div>\n')  # .stat-bar

    # ================================================================== #
    # Section 2: Mode comparison — 5 s window                            #
    # ================================================================== #
    w('<h2>Ablation mode comparison — 5 s window</h2>\n')
    w('<div class="table-wrap"><table>\n')
    w('<thead><tr>')
    for col in ("Mode", "Runs", "DR", "FPR", "Proc time (mean)",
                "Attack cycles", "Calib cycles", ""):
        align = ' class="r"' if col not in ("Mode", "") else ""
        w(f'<th{align}>{col}</th>')
    w('</tr></thead>\n<tbody>\n')

    mode_label = {
        "FULL":             "FULL",
        "NO_MULTI_WINDOW":  "NO_MULTI_WINDOW",
        "NO_DUAL_MECH":     "NO_DUAL_MECH",
        "FIXED_THRESHOLD":  "FIXED_THRESHOLD",
    }

    for mode in MODES:
        d     = agg.get(mode, {}).get("5s", {})
        dr_v  = d.get("dr",   [])
        fpr_v = d.get("fpr",  [])
        pr_v  = d.get("proc", [])
        n     = len(dr_v)

        dr_m  = _mean(dr_v);  dr_sd  = _stdev(dr_v)
        fpr_m = _mean(fpr_v); fpr_sd = _stdev(fpr_v)

        dr_str  = pct_pm(dr_m,  dr_sd,  decimals=1)
        fpr_str = pct_pm(fpr_m, fpr_sd, decimals=3)

        # Attack / calib cycle totals across all runs
        att_total  = sum(r.attack_n("5s") for _, r in runs if r.mode == mode)
        cal_total  = sum(r.calib_n("5s")  for _, r in runs if r.mode == mode)

        w('<tr>')
        w(f'<td class="mode-col">{mode_label[mode]}</td>')
        w(f'<td class="r dim">{n}</td>')
        w(f'<td class="r em">{dr_str}</td>')
        w(f'<td class="r em">{fpr_str}</td>')
        w(f'<td class="r dim">{ms_fmt(_mean(pr_v))}</td>')
        w(f'<td class="r dim">{att_total}</td>')
        w(f'<td class="r dim">{cal_total}</td>')
        w(f'<td>{_badge(dr_m, fpr_m, n)}</td>')
        w('</tr>\n')

    w('</tbody></table></div>\n')

    # ================================================================== #
    # Section 3: Window breakdown — FULL mode                            #
    # ================================================================== #
    w('<h2>Window breakdown — FULL mode</h2>\n')
    w('<div class="table-wrap"><table>\n')
    w('<thead><tr>')
    for col in ("Window", "Runs", "DR", "FPR", "Proc time (mean)",
                "Attack cycles", "Calib cycles", "Notes"):
        align = ' class="r"' if col not in ("Window", "Notes") else ""
        w(f'<th{align}>{col}</th>')
    w('</tr></thead>\n<tbody>\n')

    window_note = {
        "5s":   "Primary — OAKF warm-up 3 cycles (~15 s)",
        "30s":  "Slow-burst detection",
        "120s": "Sustained / low-rate detection",
    }

    for win in WINDOWS:
        d     = agg.get("FULL", {}).get(win, {})
        dr_v  = d.get("dr",   [])
        fpr_v = d.get("fpr",  [])
        pr_v  = d.get("proc", [])
        n     = len(dr_v)

        dr_m  = _mean(dr_v);  dr_sd  = _stdev(dr_v)
        fpr_m = _mean(fpr_v); fpr_sd = _stdev(fpr_v)

        dr_str  = pct_pm(dr_m,  dr_sd,  decimals=1)
        fpr_str = pct_pm(fpr_m, fpr_sd, decimals=3)

        att_total = sum(r.attack_n(win) for _, r in runs if r.mode == "FULL")
        cal_total = sum(r.calib_n(win)  for _, r in runs if r.mode == "FULL")

        w('<tr>')
        w(f'<td class="mode-col">{win}</td>')
        w(f'<td class="r dim">{n}</td>')
        w(f'<td class="r em">{dr_str}</td>')
        w(f'<td class="r em">{fpr_str}</td>')
        w(f'<td class="r dim">{ms_fmt(_mean(pr_v))}</td>')
        w(f'<td class="r dim">{att_total}</td>')
        w(f'<td class="r dim">{cal_total}</td>')
        w(f'<td class="dim">{window_note.get(win, "")}</td>')
        w('</tr>\n')

    w('</tbody></table></div>\n')

    # ================================================================== #
    # Section 4: Per-chunk DR grid — FULL / 5 s                         #
    # ================================================================== #
    w('<h2>Per-chunk detection rate — FULL mode · 5 s window</h2>\n')

    has_data = any(v is not None for v in chunk_grid.values())
    if not has_data:
        w('<span class="no-data">No FULL-mode runs with attack data found.</span>\n')
    else:
        w('<div class="dr-grid">\n')
        for cid in range(30):
            dr = chunk_grid.get(cid)
            bg, fg = _dr_colors(dr)
            label  = f"{dr * 100:.0f}%" if dr is not None else "—"
            w(f'<div class="dr-cell" style="background:{bg};color:{fg};">'
              f'<div class="dr-cell-id">c{cid:02d}</div>{label}</div>\n')
        w('</div>\n')  # .dr-grid

        w("""<div class="legend">
  <span>Legend:</span>
  <span class="legend-chip" style="background:#0f2a14;color:#3fb950;">≥ 99%</span>
  <span class="legend-chip" style="background:#2d2208;color:#d29922;">95–99%</span>
  <span class="legend-chip" style="background:#2d1608;color:#db6d28;">80–95%</span>
  <span class="legend-chip" style="background:#2d0c0a;color:#f85149;">&lt; 80%</span>
  <span class="legend-chip" style="background:#21262d;color:#6e7681;">no data</span>
</div>
""")

    # ================================================================== #
    # Section 5: File inventory                                          #
    # ================================================================== #
    w('<h2>CSV files loaded</h2>\n')
    if not files:
        w('<span class="no-data">No run_*.csv files found in logs directory.</span>\n')
    else:
        w('<div class="file-list">\n')
        for fpath in sorted(files):
            fname = os.path.basename(fpath)
            size  = os.path.getsize(fpath)
            size_str = (f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B")
            w(f'<span class="fname">{fname}</span>'
              f'<span class="fsize">  ({size_str})</span><br>\n')
        w('</div>\n')

    w('</body></html>\n')
    return "".join(p)


# ---------------------------------------------------------------------------
# Per-chunk report builder
# ---------------------------------------------------------------------------

def build_chunk_html(chunk_id: int, chunk_runs: list) -> str:
    """Build a detailed HTML report for one chunk across all available modes.

    chunk_runs: list of (filepath, RunResult) where every run.chunk_id == chunk_id.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Index by mode; if a mode was run more than once for this chunk, keep last.
    by_mode: dict = {}
    for _fpath, run in chunk_runs:
        by_mode[run.mode] = run

    full_run = by_mode.get("FULL")

    p: list = []
    w = p.append

    # ---- Head ----
    w(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chunk {chunk_id:02d} — Detailed Results</title>
<style>{CSS}</style>
</head>
<body>
<a class="nav-back" href="report.html">← Back to main report</a>
<header>
  <h1>Chunk {chunk_id:02d} — Detailed Results</h1>
  <p>Generated {now} &nbsp;|&nbsp;
     {len(chunk_runs)} mode(s) available &nbsp;|&nbsp;
     Targets: DR ≥ {TARGET_DR*100:.0f}%,  FPR &lt; {TARGET_FPR*100:.2f}%</p>
</header>
""")

    # ================================================================== #
    # Section 1: Mode comparison — 5 s window                            #
    # ================================================================== #
    w('<h2>Mode comparison — 5 s window</h2>\n')
    w('<div class="table-wrap"><table>\n')
    w('<thead><tr>')
    for col in ("Mode", "DR", "FPR", "Proc time (mean)",
                "Attack cycles", "Calib cycles", ""):
        align = ' class="r"' if col not in ("Mode", "") else ""
        w(f'<th{align}>{col}</th>')
    w('</tr></thead>\n<tbody>\n')

    for mode in MODES:
        run = by_mode.get(mode)
        if run is None:
            dr_m = fpr_m = proc_m = None
            att_n = cal_n = 0
        else:
            dr_m   = run.dr("5s")
            fpr_m  = run.fpr("5s")
            proc_m = run.proc("5s")
            att_n  = run.attack_n("5s")
            cal_n  = run.calib_n("5s")

        w('<tr>')
        w(f'<td class="mode-col">{mode}</td>')
        w(f'<td class="r em">{pct(dr_m, 1)}</td>')
        w(f'<td class="r em">{pct(fpr_m, 3)}</td>')
        w(f'<td class="r dim">{ms_fmt(proc_m)}</td>')
        w(f'<td class="r dim">{att_n}</td>')
        w(f'<td class="r dim">{cal_n}</td>')
        w(f'<td>{_badge(dr_m, fpr_m, 1 if run is not None else 0)}</td>')
        w('</tr>\n')

    w('</tbody></table></div>\n')

    # ================================================================== #
    # Section 2: Window breakdown — FULL mode                            #
    # ================================================================== #
    w('<h2>Window breakdown — FULL mode</h2>\n')

    if full_run is None:
        w('<span class="no-data">No FULL-mode run available for this chunk.</span>\n')
    else:
        window_note = {
            "5s":   "Primary — OAKF warm-up 3 cycles (~15 s)",
            "30s":  "Slow-burst detection",
            "120s": "Sustained / low-rate detection",
        }
        w('<div class="table-wrap"><table>\n')
        w('<thead><tr>')
        for col in ("Window", "DR", "FPR", "Proc time (mean)",
                    "Attack cycles", "Calib cycles", "Notes"):
            align = ' class="r"' if col not in ("Window", "Notes") else ""
            w(f'<th{align}>{col}</th>')
        w('</tr></thead>\n<tbody>\n')

        for win in WINDOWS:
            w('<tr>')
            w(f'<td class="mode-col">{win}</td>')
            w(f'<td class="r em">{pct(full_run.dr(win), 1)}</td>')
            w(f'<td class="r em">{pct(full_run.fpr(win), 3)}</td>')
            w(f'<td class="r dim">{ms_fmt(full_run.proc(win))}</td>')
            w(f'<td class="r dim">{full_run.attack_n(win)}</td>')
            w(f'<td class="r dim">{full_run.calib_n(win)}</td>')
            w(f'<td class="dim">{window_note.get(win, "")}</td>')
            w('</tr>\n')

        w('</tbody></table></div>\n')

    # ================================================================== #
    # Section 3: Signal trace — FULL mode, 5 s window                    #
    # ================================================================== #
    w('<h2>Signal trace — FULL mode · 5 s window</h2>\n')

    if full_run is None:
        w('<span class="no-data">No FULL-mode run available for this chunk.</span>\n')
    else:
        trace_rows = sorted(
            full_run.cycles.get("5s", []),
            key=lambda r: float(r.get("elapsed_s", 0)),
        )

        if not trace_rows:
            w('<span class="no-data">No 5 s window cycles recorded.</span>\n')
        else:
            w('<div class="table-wrap"><table>\n')
            w('<thead><tr>')
            for col in ("elapsed_s", "phase", "syn", "synack",
                        "entropy", "revisit", "synack_ratio", "alert"):
                w(f'<th>{col}</th>')
            w('</tr></thead>\n<tbody>\n')

            for row in trace_rows:
                phase = row.get("phase", "")
                alert = row.get("alert", "0")

                phase_cls = {
                    "calibration": "phase-cal",
                    "attack":      "phase-att",
                    "post":        "phase-post",
                }.get(phase, "dim")

                alert_cls  = "alert-yes" if alert == "1" else "alert-no"
                alert_text = "ALERT" if alert == "1" else "·"

                elapsed      = float(row.get("elapsed_s", 0))
                syn          = row.get("syn", "0")
                synack       = row.get("synack", "0")
                entropy      = float(row.get("entropy", 0))
                revisit      = float(row.get("revisit", 0))
                synack_ratio = float(row.get("synack_ratio", 0))

                w('<tr>')
                w(f'<td class="r dim">{elapsed:.2f}s</td>')
                w(f'<td class="{phase_cls}">{phase}</td>')
                w(f'<td class="r">{syn}</td>')
                w(f'<td class="r dim">{synack}</td>')
                w(f'<td class="r dim">{entropy:.4f}</td>')
                w(f'<td class="r dim">{revisit:.4f}</td>')
                w(f'<td class="r dim">{synack_ratio:.4f}</td>')
                w(f'<td class="{alert_cls}">{alert_text}</td>')
                w('</tr>\n')

            w('</tbody></table></div>\n')

    w('</body></html>\n')
    return "".join(p)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Reading CSVs from: {LOGS_DIR}")
    runs = load_runs(LOGS_DIR)
    print(f"Loaded {len(runs)} run(s).")

    if not runs:
        print("[WARN] No CSVs found — report will show empty state.")

    agg        = aggregate(runs)
    chunk_grid = chunk_dr_map(runs)
    html       = build_html(runs, agg, chunk_grid)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Report written: {OUTPUT_PATH}  ({len(html):,} bytes)")

    # -- Per-chunk reports --
    by_chunk: dict = defaultdict(list)
    for fpath, run in runs:
        by_chunk[run.chunk_id].append((fpath, run))

    chunk_count = 0
    for chunk_id in sorted(by_chunk.keys()):
        chunk_html = build_chunk_html(chunk_id, by_chunk[chunk_id])
        chunk_path = os.path.join(LOGS_DIR, f"report_chunk_{chunk_id:02d}.html")
        with open(chunk_path, "w", encoding="utf-8") as fh:
            fh.write(chunk_html)
        chunk_count += 1

    print(f"Per-chunk reports written: {chunk_count}")


if __name__ == "__main__":
    main()
