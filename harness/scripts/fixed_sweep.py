#!/usr/bin/env python3
"""
fixed_sweep.py — log-only fixed-threshold multiplier sweep (adaptive-claim test).

Re-scores existing run logs ONLY (no live experiments). For a global multiplier
m, flags each signal with the CORRECTED band |v - mean| > m*sigma (no extra-mean
bug), applies FULL logic (M1 = entropy OR revisit anom, M2 = synack anom,
alert = M1 AND M2), and reports DR / flood-free FPR as a function of m. The
question: can any single fixed m match OAKF's operating point on BOUN?

BOUN: 10 FULL run logs, 5s window, pre-registered primary label
      (pulse-overlap OR syn >= K, K=5000). OAKF point = the actual logged alert.
CIC : canonical-30 FULL logs, 5s, phase labels (attack vs calibration).

Outputs: logs/boun/fixed_sweep.csv, logs/boun/fixed_sweep.png (OAKF marked),
         logs/boun/fixed_sweep_cic.csv.

Run with an interpreter that has matplotlib (ryu-env):
    ~sdnuser/ryu-env/bin/python harness/scripts/fixed_sweep.py
"""
import csv, glob, os, re, statistics as st, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import recompute_boun_labels as rc

SIGCOL = {"entropy": "entropy", "revisit": "revisit", "synack": "synack_ratio"}
KSYN = 5000
M_LIST = [round(0.5 + 0.25 * i, 2) for i in range(int((6.0 - 0.5) / 0.25) + 1)]


def calib_ms(rows, size):
    o = {}
    for s, c in SIGCOL.items():
        v = [float(r[c]) for r in rows
             if r["window"] == f"{size}s" and r["phase"] == "calibration"]
        o[s] = (st.mean(v) if v else 0.0, st.stdev(v) if len(v) > 1 else 0.0)
    return o


def fixed_alert(vals, ms, m):
    fl = {s: (abs(vals[s] - ms[s][0]) > m * ms[s][1] if ms[s][1] > 0 else False)
          for s in SIGCOL}
    return int((fl["entropy"] or fl["revisit"]) and fl["synack"])


# ---------------- BOUN: build per-run eval windows with primary labels ----------
def load_boun():
    ptime = rc.load_tcp_times()
    runs = []
    for csvp in sorted(glob.glob(os.path.join(REPO, "logs/boun/run_b_full_*_chunk_0_FULL.csv"))):
        rid = re.search(r'(b_full_\d+)', csvp).group(1)
        rows = list(csv.DictReader(open(csvp)))
        ts, pts = rc.parse_stats(os.path.join(REPO, f"logs/boun/batch/tcpreplay_{rid}.log"))
        w2b = rc.build_wall_to_boun(pts, ptime)
        ms = calib_ms(rows, 5)
        ev = []
        oa_att = oa_d = oa_leg = oa_f = 0
        for r in rows:
            if r["window"] != "5s" or r["phase"] != "drift":
                continue
            we = float(r["timestamp"]) - ts
            if we <= 0:
                continue
            bs, be = w2b(we - 5), w2b(we)
            nlab, _ = rc.label_window(bs, be)
            syn = int(r["syn"])
            prim = "attack" if (nlab == "attack" or syn >= KSYN) else "legit"
            ev.append((prim, {s: float(r[c]) for s, c in SIGCOL.items()}))
            a = int(r["alert"])
            if prim == "attack":
                oa_att += 1; oa_d += a
            else:
                oa_leg += 1; oa_f += a
        runs.append((ms, ev,
                     (oa_d / oa_att if oa_att else None,
                      oa_f / oa_leg if oa_leg else None)))
    return runs


def sweep_boun(runs):
    out = []
    for m in M_LIST:
        drs, fps = [], []
        for ms, ev, _ in runs:
            att = d = leg = f = 0
            for prim, vals in ev:
                al = fixed_alert(vals, ms, m)
                if prim == "attack":
                    att += 1; d += al
                else:
                    leg += 1; f += al
            if att:
                drs.append(d / att)
            if leg:
                fps.append(f / leg)
        out.append((m, st.mean(drs) if drs else 0.0, st.mean(fps) if fps else 0.0))
    return out


# ---------------- CIC sanity: phase-based, canonical-30 FULL --------------------
def sweep_cic():
    allb = sorted(glob.glob(os.path.join(REPO, "logs/run_batch_FULL_c*_chunk_*_FULL.csv")))
    have = {re.search(r'_c(\d+)_', f).group(1) for f in allb}
    files = list(allb)
    # fill missing canonical chunks (c07,c12 for FULL) from reruns
    for cc in ("00", "07", "12"):
        rr = os.path.join(REPO, f"logs/run_rerun_FULL_c{cc}_chunk_{int(cc)}_FULL.csv")
        if cc not in have and os.path.isfile(rr):
            files.append(rr)
    runs = []
    for f in files:
        rows = list(csv.DictReader(open(f)))
        ms = calib_ms(rows, 5)
        att = [r for r in rows if r["window"] == "5s" and r["phase"] == "attack"]
        cal = [r for r in rows if r["window"] == "5s" and r["phase"] == "calibration"]
        runs.append((ms, att, cal))
    out = []
    for m in M_LIST:
        drs, fps = [], []
        for ms, att, cal in runs:
            if att:
                drs.append(sum(fixed_alert({s: float(r[c]) for s, c in SIGCOL.items()}, ms, m)
                               for r in att) / len(att))
            if cal:
                fps.append(sum(fixed_alert({s: float(r[c]) for s, c in SIGCOL.items()}, ms, m)
                               for r in cal) / len(cal))
        out.append((m, st.mean(drs) if drs else 0.0, st.mean(fps) if fps else 0.0))
    return out, len(files)


def main():
    runs = load_boun()
    sw = sweep_boun(runs)
    oakf_dr = st.mean([r[2][0] for r in runs if r[2][0] is not None])
    oakf_fp = st.mean([r[2][1] for r in runs if r[2][1] is not None])

    with open(os.path.join(REPO, "logs/boun/fixed_sweep.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["multiplier_m", "fixed_DR", "fixed_flood_free_FPR"])
        for m, dr, fp in sw:
            w.writerow([m, f"{dr:.4f}", f"{fp:.4f}"])

    print(f"OAKF actual BOUN 5s (primary): DR={100*oakf_dr:.2f}%  "
          f"flood-free FPR={100*oakf_fp:.3f}%\n")
    print(f"  {'m':>5} {'fixedDR':>8} {'fixedFPR':>9}")
    for m, dr, fp in sw:
        mark = "  <== dominates OAKF" if (dr >= oakf_dr and fp <= oakf_fp + 1e-9) else ""
        print(f"  {m:>5.2f} {100*dr:>7.2f}% {100*fp:>8.3f}%{mark}")

    dom = [(m, dr, fp) for m, dr, fp in sw if dr >= oakf_dr and fp <= oakf_fp + 1e-9]
    best_dr = max(sw, key=lambda x: x[1])
    pos = [x for x in sw if x[1] > 0]
    best_fp = min(pos, key=lambda x: x[2]) if pos else (None, 0, 0)
    print(f"\nbest fixed DR : {100*best_dr[1]:.2f}% at m={best_dr[0]} "
          f"costing flood-free FPR={100*best_dr[2]:.3f}%")
    print(f"best fixed FPR: {100*best_fp[2]:.3f}% at m={best_fp[0]} "
          f"giving DR={100*best_fp[1]:.2f}%")
    print(f"dominating m (DR>=OAKF AND FPR<=OAKF): "
          f"{[(m, round(100*dr,1), round(100*fp,2)) for m,dr,fp in dom] or 'NONE'}")
    print(f"VERDICT: OAKF {'DOMINATES' if not dom else 'does NOT dominate'} the BOUN fixed curve")

    # plot
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 5))
    xs = [100 * fp for _, _, fp in sw]
    ys = [100 * dr for _, dr, _ in sw]
    ax.plot(xs, ys, '-o', ms=3, color="C0", label="fixed threshold (m=0.5..6)")
    for m, dr, fp in sw:
        if m in (0.5, 1.0, 1.5, 2.0, 3.0, 6.0):
            ax.annotate(f"m={m}", (100 * fp, 100 * dr), fontsize=7,
                        xytext=(3, 2), textcoords="offset points")
    ax.scatter([100 * oakf_fp], [100 * oakf_dr], color="red", zorder=5, s=90,
               marker="*", label=f"OAKF ({100*oakf_dr:.0f}% DR, {100*oakf_fp:.1f}% FPR)")
    ax.set_xlabel("flood-free FPR (%)")
    ax.set_ylabel("DR (%)")
    ax.set_title("BOUN: fixed-threshold DR-FPR sweep vs OAKF (5s, primary)")
    ax.grid(alpha=0.3)
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(REPO, "logs/boun/fixed_sweep.png"), dpi=130)
    print("\n[saved] logs/boun/fixed_sweep.csv, logs/boun/fixed_sweep.png")

    # CIC sanity
    csw, ncic = sweep_cic()
    with open(os.path.join(REPO, "logs/boun/fixed_sweep_cic.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["multiplier_m", "fixed_DR", "fixed_FPR"])
        for m, dr, fp in csw:
            w.writerow([m, f"{dr:.4f}", f"{fp:.4f}"])
    # find m matching OAKF-CIC (~95.5% DR, ~0.08% FPR)
    matches = [(m, dr, fp) for m, dr, fp in csw if dr >= 0.955 and fp <= 0.001]
    print(f"\nCIC sanity sweep ({ncic} FULL runs, 5s):")
    for m, dr, fp in csw:
        if m in (0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0):
            print(f"  m={m:>4}: DR={100*dr:6.2f}%  FPR={100*fp:6.3f}%")
    print(f"  fixed m matching OAKF-CIC (DR>=95.5% & FPR<=0.1%): "
          f"{[(m, round(100*dr,1)) for m,dr,fp in matches][:6] or 'NONE'}")


if __name__ == "__main__":
    main()
