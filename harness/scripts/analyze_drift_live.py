#!/usr/bin/env python3
"""
analyze_drift_live.py — score the LIVE drift runs and re-score the fixed-m sweep.

Reads logs/boun/drift_live/{schedule_<id>.json, run_<id>_chunk_0_FULL.csv,
cpu_<id>.csv}. Labels each 5s window (calibration / drift-legit / attack-early|
mid|late) from the recorded wall-clock schedule. OAKF DR/FPR come from the LIVE
logged entropy anomaly flag (entropy_anom = the real OAKF k=3 decision); the
fixed threshold is re-scored offline from the logged entropy with the corrected
band |v-mean|>m*sigma frozen on the calibration segment, swept over m.

Run with matplotlib-capable interpreter:  ~sdnuser/ryu-env/bin/python
Usage: analyze_drift_live.py [pilot|batch]
"""
import csv, glob, json, os, statistics as st, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DIR = os.path.join(REPO, "logs", "boun", "drift_live")
sys.path.insert(0, os.path.join(REPO, "harness", "detector"))
from oakf import OAKF                       # real filter (for band trajectory)

OAKF_ENTROPY = dict(process_noise=1e-3, measurement_noise=0.5,
                    deviation_multiplier=3.0, warmup_cycles=3)   # published, unchanged
M_LIST = sorted(set([round(0.5 + 0.25 * i, 2) for i in range(23)]
                    + [float(x) for x in range(7, 46)]))
CAL_LO, CAL_HI = 10.0, 80.0                 # gen-elapsed calib segment (low baseline)


def load_run(run_id):
    sched = json.load(open(os.path.join(DIR, f"schedule_{run_id}.json")))
    t0 = sched["t0"]
    atks = sched["attacks"]
    ds = sched["drift_start"]
    rows = []
    with open(os.path.join(DIR, f"run_{run_id}_chunk_0_FULL.csv"), newline="") as f:
        for r in csv.DictReader(f):
            if r["window"] != "5s":
                continue
            gee = float(r["timestamp"]) - t0          # gen-elapsed at window end
            gst = gee - 5
            if gee < 8 or gee > sched["dur"] + 3:
                continue
            # label
            label, grp = None, None
            for a in atks:
                ov = min(gee, a["end"]) - max(gst, a["start"])
                if ov >= 2.5:
                    label, grp = "attack", a["group"]
                    break
            if label is None:
                near_atk = any(a["start"] - 6 <= gee <= a["end"] + 6 for a in atks)
                if CAL_LO <= gee <= CAL_HI:
                    label = "calib"
                elif gee > ds and not near_atk:
                    label = "drift_legit"
                else:
                    label = "exclude"
            rows.append({"gee": gee, "entropy": float(r["entropy"]),
                         "revisit": float(r["revisit"]), "synack": float(r["synack_ratio"]),
                         "oakf_anom": int(r["entropy_anom"]),
                         "oakf_thresh": float(r["entropy_thresh"]),
                         "label": label, "group": grp})
    return sched, rows


def oakf_band(rows):
    """Re-run real OAKF on the logged entropy to recover x +/- band per window."""
    o = OAKF(**OAKF_ENTROPY)
    xs, bands, anoms = [], [], []
    for r in rows:
        a, resid, thr = o.update(r["entropy"])
        xs.append(o.x); bands.append(thr); anoms.append(int(a))
    return xs, bands, anoms


def fixed_calib(rows):
    v = [r["entropy"] for r in rows if r["label"] == "calib"]
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def score(rows, alert):
    atk = [i for i, r in enumerate(rows) if r["label"] == "attack"]
    leg = [i for i, r in enumerate(rows) if r["label"] == "drift_legit"]
    dr = sum(alert[i] for i in atk) / len(atk) if atk else None
    fpr = sum(alert[i] for i in leg) / len(leg) if leg else None
    return dr, fpr, len(atk), len(leg)


def drift_mag(rows):
    calib = [r["entropy"] for r in rows if r["label"] == "calib"]
    late = [r["entropy"] for r in rows if r["label"] == "drift_legit" and r["gee"] > 400]
    ea = [r["entropy"] for r in rows if r["label"] == "attack" and r["gee"] < 160]
    return (st.mean(calib) if calib else 0, st.mean(late) if late else 0,
            st.mean(ea) if ea else 0)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "pilot"
    ids = sorted(os.path.basename(p)[len("schedule_"):-len(".json")]
                 for p in glob.glob(os.path.join(DIR, "schedule_*.json")))
    if mode == "pilot":
        ids = [i for i in ids if "pilot" in i] or ids[:1]
    else:
        ids = [i for i in ids if "pilot" not in i] or ids
    print(f"runs: {ids}")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    all_oakf_dr, all_oakf_fpr = [], []
    sweep = {m: {"dr": [], "fpr": []} for m in M_LIST}
    mags = []
    first_rows = None
    for rid in ids:
        sched, rows = load_run(rid)
        if first_rows is None:
            first_rows = (sched, rows)
        cm, lm, eam = drift_mag(rows)
        mags.append((cm, lm, eam))
        d, f, na, nl = score(rows, [r["oakf_anom"] for r in rows])
        all_oakf_dr.append(d); all_oakf_fpr.append(f)
        fm, fs = fixed_calib(rows)
        for m in M_LIST:
            fl = [abs(r["entropy"] - fm) > m * fs for r in rows]
            dd, ff, _, _ = score(rows, fl)
            sweep[m]["dr"].append(dd); sweep[m]["fpr"].append(ff)
        print(f"  {rid}: calib E={cm:.2f} late-legit E={lm:.2f} early-atk E={eam:.2f} "
              f"| OAKF DR={100*d:.0f}% FPR={100*f:.1f}% (atkW={na}, legW={nl})")

    cm = st.mean([m[0] for m in mags]); lm = st.mean([m[1] for m in mags])
    eam = st.mean([m[2] for m in mags])
    print(f"\n[A] LIVE DRIFT MAGNITUDE: entropy calib {cm:.2f} -> late-legit {lm:.2f} "
          f"(+{lm-cm:.2f} bits); early-attack {eam:.2f}; "
          f"late-legit vs early-attack gap = {abs(lm-eam):.2f} -> "
          f"stress {'MET' if abs(lm-eam)<0.8 else 'PARTIAL'}")

    O_DR = st.mean([d for d in all_oakf_dr if d is not None])
    O_FPR = st.mean([f for f in all_oakf_fpr if f is not None])
    O_DR_sd = st.stdev(all_oakf_dr) if len(all_oakf_dr) > 1 else 0
    O_FPR_sd = st.stdev(all_oakf_fpr) if len(all_oakf_fpr) > 1 else 0

    # pilot trace plot (first run)
    sched, rows = first_rows
    xs, bands, _ = oakf_band(rows)
    fm, fs = fixed_calib(rows)
    gee = [r["gee"] for r in rows]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(gee, [r["entropy"] for r in rows], 'o-', ms=3, color="0.4", label="live entropy")
    ax.plot(gee, xs, color="C0", lw=1.4, label="OAKF tracked mean")
    ax.fill_between(gee, [x - b for x, b in zip(xs, bands)], [x + b for x, b in zip(xs, bands)],
                    color="C0", alpha=0.18, label="OAKF band (k=3)")
    ax.axhline(fm + 3 * fs, color="C3", ls="--", lw=1.2, label="fixed band (m=3, frozen)")
    ax.axhline(fm - 3 * fs, color="C3", ls="--", lw=1.2)
    for a in sched["attacks"]:
        ax.axvspan(a["start"], a["end"], color="red", alpha=0.15)
    ax.axvspan(CAL_LO, CAL_HI, color="green", alpha=0.08)
    ax.set_xlabel("gen elapsed s (green=calib, red=attack)")
    ax.set_ylabel("source-IP entropy (bits)")
    ax.set_title("LIVE drift: legit baseline rises, OAKF band tracks, fixed band frozen")
    ax.legend(loc="upper left", fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(DIR, "drift_live_pilot.png"), dpi=130)
    print(f"[saved] {DIR}/drift_live_pilot.png")

    print(f"\n[C] OAKF live operating point: DR={100*O_DR:.1f}%±{100*O_DR_sd:.1f} "
          f"FPR={100*O_FPR:.1f}%±{100*O_FPR_sd:.1f}  (n={len(ids)} runs)")

    if mode == "pilot":
        # gate: OAKF detects all groups & ~0 FPR; fixed(m=3) FPs on drifted legit
        sched, rows = first_rows
        grpdet = {}
        for g in ("early", "mid", "late"):
            gi = [i for i, r in enumerate(rows) if r["group"] == g]
            grpdet[g] = (sum(rows[i]["oakf_anom"] for i in gi), len(gi))
        fm, fs = fixed_calib(rows)
        f3 = [abs(r["entropy"] - fm) > 3 * fs for r in rows]
        d3, fp3, _, _ = score(rows, f3)
        gate = (O_DR >= 0.9 and O_FPR <= 0.05 and all(v[0] > 0 for v in grpdet.values()))
        print(f"\n[B] GATE: OAKF per-group detect {grpdet}; fixed(m=3) DR={100*d3:.0f}% "
              f"FPR={100*fp3:.0f}%")
        print(f"    GATE {'PASS' if gate else 'FAIL'} "
              f"(OAKF detects all 3 groups at ~0 FPR while fixed FPs on drift)")
        return

    # batch verdict + sweep
    print(f"\n    live fixed-threshold sweep under drift (mean over {len(ids)} runs):")
    curve = []
    for m in M_LIST:
        dr = st.mean([x for x in sweep[m]["dr"] if x is not None])
        fpr = st.mean([x for x in sweep[m]["fpr"] if x is not None])
        curve.append((m, dr, fpr))
    for m, dr, fpr in curve:
        if m in (0.5, 1, 2, 3, 4, 6, 8, 10, 13, 16, 20):
            mk = "  <== dominates OAKF" if (dr >= O_DR and fpr <= O_FPR + 1e-9) else ""
            print(f"      m={m:>5.1f}  DR={100*dr:5.1f}%  FPR={100*fpr:5.1f}%{mk}")
    dom = [(m, dr, fpr) for m, dr, fpr in curve if dr >= O_DR and fpr <= O_FPR + 1e-9]
    okdr = [x for x in curve if x[1] >= O_DR - 1e-9]
    best_fp = min(okdr, key=lambda x: x[2]) if okdr else None
    print(f"\n    KEY VERDICT: {'NO' if not dom else 'YES'} fixed m has DR>=OAKF AND FPR<=OAKF"
          f"  =>  OAKF {'DOMINATES' if not dom else 'does NOT dominate'} the LIVE fixed curve")
    if best_fp:
        print(f"    lowest fixed FPR while DR>=OAKF({100*O_DR:.0f}%) = {100*best_fp[2]:.1f}% @ m={best_fp[0]}")

    with open(os.path.join(DIR, "fixed_sweep_drift_live.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["m", "fixed_DR", "fixed_FPR"])
        for m, dr, fpr in curve:
            w.writerow([m, f"{dr:.4f}", f"{fpr:.4f}"])
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([100 * fpr for _, _, fpr in curve], [100 * dr for _, dr, _ in curve],
            '-o', ms=3, color="C0", label="fixed threshold (LIVE drift)")
    for m, dr, fpr in curve:
        if m in (1, 3, 6, 10, 16):
            ax.annotate(f"m={m:g}", (100 * fpr, 100 * dr), fontsize=7,
                        xytext=(3, 2), textcoords="offset points")
    ax.errorbar([100 * O_FPR], [100 * O_DR], xerr=[100 * O_FPR_sd], yerr=[100 * O_DR_sd],
                fmt='*', color="red", ms=14, capsize=3,
                label=f"OAKF live ({100*O_DR:.0f}% DR, {100*O_FPR:.1f}% FPR)")
    ax.set_xlabel("FPR on drifted-legit (%)"); ax.set_ylabel("DR (%)")
    ax.set_title("LIVE drift: fixed DR-FPR curve vs OAKF (entropy channel)")
    ax.grid(alpha=0.3); ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(DIR, "fixed_sweep_drift_live.png"), dpi=130)
    print(f"    [saved] {DIR}/fixed_sweep_drift_live.csv, fixed_sweep_drift_live.png")

    # CPU secondary
    cpus = []
    for rid in ids:
        p = os.path.join(DIR, f"cpu_{rid}.csv")
        if os.path.isfile(p):
            v = [float(r["ryu_cpu_pct"]) for r in csv.DictReader(open(p))]
            if v:
                cpus.append((st.mean(v), max(v)))
    if cpus:
        print(f"\n    controller CPU (detector ON, live drift): "
              f"mean {st.mean([c[0] for c in cpus]):.0f}%  peak {max(c[1] for c in cpus):.0f}%")


if __name__ == "__main__":
    main()
