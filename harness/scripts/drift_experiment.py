#!/usr/bin/env python3
"""
drift_experiment.py — controlled OFFLINE test: does OAKF's online threshold beat
a fixed threshold at ANY multiplier under a NON-STATIONARY legitimate baseline?

Everything is synthetic/controlled BUT the signals are computed by the REAL
detector code (multi_window_detector_v2.shannon_entropy / WindowState) and scored
by the REAL OAKF with UNCHANGED published params (k=3, Q, R, warmup). No live
experiment, no thesis rewrite.

Isolation: the mechanism under test is thresholding of the SOURCE-IP ENTROPY
signal — the signal whose legitimate baseline drifts. Legitimate traffic ramps
its active-source count N(t) over the trial (log2(N) => rising entropy baseline).
Attacks are spoofed-source bursts that add a ~constant entropy DEVIATION D above
the CURRENT baseline (same signature magnitude at each injection), so detection
can be compared as the baseline moves. The drift range is set so LATE-legit
entropy reaches EARLY-attack entropy (the defining stress: the two become
absolutely indistinguishable, so no single frozen level can separate them).

Fixed threshold = the CORRECTED band |v-mean| > m*sigma (from calib), swept over
m (best-case fixed at any multiplier). OAKF = the real filter at k=3.

Phase 1 pilot (1 trial) + GATE, then Phase 2 batch (R=10) + fixed-m sweep.
Outputs (logs/boun/drift/): drift_trace.csv, drift_pilot.png, fixed_sweep_drift.csv,
fixed_sweep_drift.png.
"""
import csv, os, sys, types, statistics as st, random

# ---- import REAL detector signal code via a minimal ryu stub (as eval_boun) ----
def _stub_ryu():
    for n in ['ryu', 'ryu.base', 'ryu.base.app_manager', 'ryu.controller',
              'ryu.controller.ofp_event', 'ryu.controller.handler', 'ryu.ofproto',
              'ryu.ofproto.ofproto_v1_3', 'ryu.lib', 'ryu.lib.packet', 'ryu.lib.hub']:
        sys.modules[n] = types.ModuleType(n)
    sys.modules['ryu.base.app_manager'].RyuApp = type('R', (object,), {})
    sys.modules['ryu.controller.ofp_event'].__getattr__ = lambda n: object()
    h = sys.modules['ryu.controller.handler']
    h.CONFIG_DISPATCHER = 1; h.MAIN_DISPATCHER = 2
    h.set_ev_cls = lambda *a, **k: (lambda f: f)
    sys.modules['ryu.ofproto.ofproto_v1_3'].OFP_VERSION = 4
    for a in ['packet', 'ipv4', 'tcp']:
        setattr(sys.modules['ryu.lib.packet'], a, object())

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "logs", "boun", "drift")
sys.path.insert(0, os.path.join(REPO, "harness", "detector"))
_stub_ryu()
import multi_window_detector_v2 as D
OAKF = D.OAKF
OAKF_PARAMS = D.OAKF_PARAMS          # unchanged published params
shannon_entropy = D.shannon_entropy   # REAL signal code
WindowState = D.WindowState

SYN, SYNACK = 0x02, 0x12
T = 60                # windows (5 s each -> 300 s trial)
CALIB = 12            # calibration/warmup segment (low baseline)
E0 = 4.5              # legit entropy at t=0  (~2^4.5=23 sources)
D_ATK = 3.0          # attack entropy deviation above current baseline (bits)
ATK_CENTERS = (18, 36, 54)      # early / mid / late
ATK_SPAN = 1                    # +-1 window => 3-window sustained bursts
# Drift range so LATE legit entropy == EARLY-attack entropy:
#   E1 = E0 + D/(1 - t_early/(T-1))
E1 = E0 + D_ATK / (1 - ATK_CENTERS[0] / (T - 1))
# Wide sweep: fine 0.5..6 (conventional) then coarse to 25 so the curve reveals
# BOTH arms of the fixed tradeoff — the FP arm (low m) and the miss arm (high m,
# band finally clears late-legit but that is the same level as early-attack).
M_LIST = sorted(set([round(0.5 + 0.25 * i, 2) for i in range(int((6.0 - 0.5) / 0.25) + 1)]
                    + [float(x) for x in range(7, 26)]))


def is_attack(t):
    return any(abs(t - c) <= ATK_SPAN for c in ATK_CENTERS)


def base_entropy(t):
    """Target legit entropy at window t (linear drift E0 -> E1)."""
    return E0 + (E1 - E0) * t / (T - 1)


def build_window(t, rng):
    """Construct a window's packets with the REAL WindowState; return signals.

    Legit: N uniform sources, each 1 SYN + 1 SYN-ACK (synack_ratio~1),
    entropy ~ log2(N). N jittered for per-window noise.
    Attack: add M spoofed singleton SYNs to raise entropy by ~D_ATK above the
    CURRENT legit level (M scaled to the baseline => constant-magnitude signature).
    """
    win = WindowState("5s", 5)
    b = base_entropy(t)
    N = max(2, int(round(2 ** b * rng.uniform(0.9, 1.1))))
    for i in range(N):
        ip = f"10.{(i >> 8) & 255}.{i & 255}.{rng.randint(1,254)}"
        win.update(ip, SYN)
        win.update(ip, SYNACK)
    atk = is_attack(t)
    if atk:
        M = int(round(N * (2 ** D_ATK - 1)))          # -> ~+D_ATK bits
        for j in range(M):
            ip = f"172.{(j >> 8) & 255}.{j & 255}.{rng.randint(1,254)}"
            win.update(ip, SYN)                         # spoofed SYN, no SYN-ACK
    s = win.compute_signals()
    return s, atk


def run_trial(seed):
    rng = random.Random(seed)
    rows = []
    for t in range(T):
        s, atk = build_window(t, rng)
        rows.append({"t": t, "attack": atk, "entropy": s["entropy"],
                     "revisit": s["revisit_ratio"], "synack": s["synack_ratio"]})
    return rows


def score_oakf(rows):
    """Real OAKF on entropy; warms on calib; returns per-window (band,x,anom)."""
    o = OAKF(**OAKF_PARAMS["entropy"])
    out = []
    for r in rows:
        anom, resid, thr = o.update(r["entropy"])
        out.append({"x": o.x, "band": thr, "anom": bool(anom)})
    return out


def fixed_calib(rows):
    v = [r["entropy"] for r in rows[:CALIB]]
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def fixed_flags(rows, mean, sd, m):
    return [abs(r["entropy"] - mean) > m * sd for r in rows]


def dr_fpr(rows, flags):
    atk = [i for i, r in enumerate(rows) if r["attack"]]
    leg = [i for i, r in enumerate(rows) if not r["attack"] and i >= CALIB]
    dr = sum(flags[i] for i in atk) / len(atk) if atk else None
    fpr = sum(flags[i] for i in leg) / len(leg) if leg else None
    return dr, fpr


def main():
    os.makedirs(OUT, exist_ok=True)
    batch = "--batch" in sys.argv
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # ---------------- Phase 0 magnitude + Phase 1 pilot ----------------
    rows = run_trial(0)
    oak = score_oakf(rows)
    fmean, fsd = fixed_calib(rows)

    # Drift magnitude (start vs end legit)
    leg = [r for r in rows if not r["attack"]]
    e_start = st.mean([r["entropy"] for r in leg[:5]])
    e_end = st.mean([r["entropy"] for r in leg[-5:]])
    rev_start = st.mean([r["revisit"] for r in leg[:5]])
    rev_end = st.mean([r["revisit"] for r in leg[-5:]])
    early_atk_E = st.mean([r["entropy"] for r in rows if r["attack"] and r["t"] < 25])

    print("=" * 74)
    print("DRIFT EXPERIMENT (synthetic/controlled; REAL signal code + OAKF; k=3 unchanged)")
    print("=" * 74)
    print(f"\n[A] DRIFT MAGNITUDE per signal (legit start vs end):")
    print(f"    entropy : {e_start:.2f} -> {e_end:.2f} bits  (+{e_end-e_start:.2f})")
    print(f"    revisit : {rev_start:.2f} -> {rev_end:.2f}")
    print(f"    synack  : ~1.0 (stationary for legit by construction)")
    print(f"    early-attack entropy = {early_atk_E:.2f}  ;  late-legit entropy = {e_end:.2f}"
          f"  -> stress {'MET' if abs(early_atk_E-e_end)<0.6 else 'WEAK'}")

    # OAKF pilot behaviour
    dr_o, fpr_o = dr_fpr(rows, [o["anom"] for o in oak])
    # per-injection detection
    det_by_grp = []
    for c in ATK_CENTERS:
        idxs = [i for i, r in enumerate(rows) if r["attack"] and abs(r["t"] - c) <= ATK_SPAN]
        det_by_grp.append(sum(oak[i]["anom"] for i in idxs))
    # representative fixed at m=3
    f3 = fixed_flags(rows, fmean, fsd, 3.0)
    dr_f3, fpr_f3 = dr_fpr(rows, f3)

    print(f"\n[B] PILOT (seed 0):")
    print(f"    OAKF: DR={100*dr_o:.0f}%  FPR={100*fpr_o:.1f}%  detections per group "
          f"(early/mid/late)={det_by_grp}")
    print(f"    fixed m=3: DR={100*dr_f3:.0f}%  FPR={100*fpr_f3:.1f}%")
    # late-legit crossing / late-attack miss demonstration across m
    late_leg = [i for i, r in enumerate(rows) if not r["attack"] and r["t"] >= 45]
    late_atk = [i for i, r in enumerate(rows) if r["attack"] and r["t"] >= 45]
    print(f"    fixed tradeoff across m (late-legit FP vs early/late-attack miss):")
    print(f"      {'m':>5} {'DR':>5} {'FPR':>6} {'lateLegFP':>10} {'lateAtkMiss':>12}")
    for m in (2.0, 3.0, 4.0, 5.0, 6.0):
        fl = fixed_flags(rows, fmean, fsd, m)
        dr, fpr = dr_fpr(rows, fl)
        llfp = sum(fl[i] for i in late_leg)
        lamiss = sum(1 for i in late_atk if not fl[i])
        print(f"      {m:>5.1f} {100*dr:>4.0f}% {100*fpr:>5.1f}% {llfp:>10} {lamiss:>12}")

    gate = (dr_o >= 0.99 and fpr_o <= 0.02 and all(g > 0 for g in det_by_grp))
    print(f"\n    GATE (OAKF detects all 3 groups, DR>=99%, FPR<=2%): "
          f"{'PASS' if gate else 'FAIL'}")

    # pilot plot
    ts = [r["t"] for r in rows]
    ent = [r["entropy"] for r in rows]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(ts, ent, 'o-', ms=3, color="0.4", label="entropy (legit drift + attacks)")
    ax.plot(ts, [o["x"] for o in oak], color="C0", lw=1.5, label="OAKF tracked mean")
    ax.fill_between(ts, [o["x"] - o["band"] for o in oak], [o["x"] + o["band"] for o in oak],
                    color="C0", alpha=0.18, label="OAKF adaptive band (k=3)")
    ax.axhline(fmean + 3 * fsd, color="C3", ls="--", lw=1.2, label="fixed band (m=3, frozen)")
    ax.axhline(fmean - 3 * fsd, color="C3", ls="--", lw=1.2)
    for c in ATK_CENTERS:
        ax.axvspan(c - ATK_SPAN - 0.5, c + ATK_SPAN + 0.5, color="red", alpha=0.12)
    ax.axvspan(-0.5, CALIB - 0.5, color="green", alpha=0.08)
    ax.set_xlabel("window (5 s each); green=calib, red=attack")
    ax.set_ylabel("source-IP entropy (bits)")
    ax.set_title("Drift: legit baseline rises, OAKF band tracks, fixed band frozen")
    ax.legend(loc="upper left", fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "drift_pilot.png"), dpi=130)

    with open(os.path.join(OUT, "drift_trace.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "attack", "entropy", "revisit", "synack",
                    "oakf_x", "oakf_band", "oakf_anom"])
        for r, o in zip(rows, oak):
            w.writerow([r["t"], int(r["attack"]), f"{r['entropy']:.4f}",
                        f"{r['revisit']:.4f}", f"{r['synack']:.4f}",
                        f"{o['x']:.4f}", f"{o['band']:.4f}", int(o["anom"])])
    print(f"\n    [saved] {OUT}/drift_trace.csv, drift_pilot.png")

    if not gate:
        print("\n*** GATE FAILED — not batching. Report the pilot as-is. ***")
        return
    if not batch:
        print("\n(Gate passed. Re-run with --batch for Phase 2.)")
        return

    # ---------------- Phase 2 batch + fixed sweep ----------------
    R = 10
    oakf_dr, oakf_fpr = [], []
    spur_oakf = []
    sweep = {m: {"dr": [], "fpr": []} for m in M_LIST}
    spur_fixed = {m: [] for m in M_LIST}
    for seed in range(R):
        rr = run_trial(seed)
        oo = score_oakf(rr)
        d_o, f_o = dr_fpr(rr, [o["anom"] for o in oo])
        oakf_dr.append(d_o); oakf_fpr.append(f_o); spur_oakf.append(f_o)
        fm, fs = fixed_calib(rr)
        for m in M_LIST:
            fl = fixed_flags(rr, fm, fs, m)
            d, f = dr_fpr(rr, fl)
            sweep[m]["dr"].append(d); sweep[m]["fpr"].append(f)
            spur_fixed[m].append(f)
    O_DR = st.mean(oakf_dr); O_FPR = st.mean(oakf_fpr)
    print("\n" + "=" * 74)
    print(f"[C] BATCH (R={R}) — OAKF operating point: DR={100*O_DR:.2f}%  FPR={100*O_FPR:.2f}%")
    print("=" * 74)
    print(f"    fixed-threshold sweep under drift:")
    print(f"      {'m':>5} {'DR':>7} {'FPR':>7}")
    curve = []
    for m in M_LIST:
        dr = st.mean(sweep[m]["dr"]); fpr = st.mean(sweep[m]["fpr"])
        curve.append((m, dr, fpr))
        mark = "  <== dominates OAKF" if (dr >= O_DR and fpr <= O_FPR + 1e-9) else ""
        if m in (0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6) or mark:
            print(f"      {m:>5.2f} {100*dr:>6.1f}% {100*fpr:>6.1f}%{mark}")
    dom = [(m, dr, fpr) for m, dr, fpr in curve if dr >= O_DR and fpr <= O_FPR + 1e-9]
    best_dr = max(curve, key=lambda x: x[1])
    # best fixed FPR among m achieving DR>=OAKF
    okdr = [x for x in curve if x[1] >= O_DR]
    best_fp = min(okdr, key=lambda x: x[2]) if okdr else None
    print(f"\n    best fixed DR = {100*best_dr[1]:.1f}% @ m={best_dr[0]} (FPR={100*best_dr[2]:.1f}%)")
    if best_fp:
        print(f"    lowest fixed FPR while DR>=OAKF = {100*best_fp[2]:.1f}% @ m={best_fp[0]}")
    else:
        print(f"    NO fixed m reaches OAKF's DR ({100*O_DR:.1f}%)")
    verdict = "OAKF DOMINATES the fixed curve under drift (pillar EARNED)" if not dom \
        else "a fixed m dominates OAKF (convenience-only; reframe)"
    print(f"\n    KEY VERDICT: {'NO' if not dom else 'YES'} fixed m has DR>=OAKF AND FPR<=OAKF"
          f"  =>  {verdict}")

    # per-signal spurious (entropy channel) OAKF vs best-DR fixed
    print(f"\n    spurious anomaly rate on drifted-legit (entropy channel):")
    print(f"      OAKF = {100*st.mean(spur_oakf):.2f}%   "
          f"fixed@m={best_dr[0]} = {100*st.mean(spur_fixed[best_dr[0]]):.2f}%")

    with open(os.path.join(OUT, "fixed_sweep_drift.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["m", "fixed_DR", "fixed_FPR"])
        for m, dr, fpr in curve:
            w.writerow([m, f"{dr:.4f}", f"{fpr:.4f}"])

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([100 * fpr for _, _, fpr in curve], [100 * dr for _, dr, _ in curve],
            '-o', ms=3, color="C0", label="fixed threshold (m=0.5..6) under drift")
    for m, dr, fpr in curve:
        if m in (1, 2, 3, 4, 6):
            ax.annotate(f"m={m}", (100 * fpr, 100 * dr), fontsize=7,
                        xytext=(3, 2), textcoords="offset points")
    ax.scatter([100 * O_FPR], [100 * O_DR], color="red", marker="*", s=110, zorder=5,
               label=f"OAKF ({100*O_DR:.0f}% DR, {100*O_FPR:.1f}% FPR)")
    ax.set_xlabel("FPR on drifted-legit (%)"); ax.set_ylabel("DR (%)")
    ax.set_title("Under drift: fixed DR-FPR curve vs OAKF (entropy channel)")
    ax.grid(alpha=0.3); ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fixed_sweep_drift.png"), dpi=130)
    print(f"\n    [saved] {OUT}/fixed_sweep_drift.csv, fixed_sweep_drift.png")


if __name__ == "__main__":
    main()
