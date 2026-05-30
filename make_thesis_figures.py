#!/usr/bin/env python3
"""Chapter 4 figures (4.1-4.6) from experiment CSV logs."""
import os, sys, glob
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOGS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/sdn-thesis/logs")
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(LOGS, "figures")
os.makedirs(OUT, exist_ok=True)

NAMES = ["timestamp","elapsed_s","phase","window","packets","unique_ips","syn",
    "synack","entropy","entropy_thresh","entropy_anom","revisit","revisit_thresh",
    "revisit_anom","synack_ratio","synack_thresh","synack_anom","mech1","mech2",
    "alert","proc_time_ms","run_id","chunk_id","ablation_mode"]
MODES = ["FULL","NO_MULTI_WINDOW","NO_DUAL_MECH","FIXED_THRESHOLD"]
LABEL = {"FULL":"Full system","NO_MULTI_WINDOW":"No multi-window",
    "NO_DUAL_MECH":"No dual-mech","FIXED_THRESHOLD":"Fixed threshold"}
BAR, BAR2, ACCENT = "#4a6fa5", "#a5b8d0", "#c0504d"
plt.rcParams.update({"font.family":"serif","font.size":11,"axes.titlesize":12,
    "axes.grid":True,"grid.color":"#dddddd","grid.linewidth":0.6,
    "figure.dpi":300,"savefig.dpi":300,"savefig.bbox":"tight"})

def load():
    fr=[]
    for f in glob.glob(os.path.join(LOGS,"*.csv")):
        b=os.path.basename(f).lower()
        try: d=pd.read_csv(f,header=0,names=NAMES,usecols=range(24))
        except Exception as e: print(f"  skip {b}: {e}"); continue
        d["__rerun"]="rerun" in b; fr.append(d)
    if not fr: sys.exit(f"No CSVs in {LOGS}")
    df=pd.concat(fr,ignore_index=True)
    df["chunk_id"]=pd.to_numeric(df["chunk_id"],errors="coerce")
    for c in ["alert","entropy","entropy_thresh","synack_ratio","synack_thresh","elapsed_s"]:
        df[c]=pd.to_numeric(df[c],errors="coerce")
    df["alert"]=df["alert"].fillna(0).astype(int)
    return df

ABLATION_CHUNKS=set(range(30))

def dedup_mode(df,mode):
    rows=df[(df["ablation_mode"]==mode)&(df["chunk_id"].isin(ABLATION_CHUNKS))].copy()
    rr=set(rows.loc[rows["__rerun"],"chunk_id"].dropna().unique())
    return rows[~((rows["chunk_id"].isin(rr))&(~rows["__rerun"]))]

def dedup_full(df): return dedup_mode(df,"FULL")

def mode_rows(df,m): return dedup_mode(df,m)

def pooled(rows,win="5s"):
    w=rows[rows["window"]==win]; a=w[w["phase"]=="attack"]; c=w[w["phase"]=="calibration"]
    dr=100*a["alert"].sum()/len(a) if len(a) else float("nan")
    fpr=100*c["alert"].sum()/len(c) if len(c) else float("nan")
    return dr,fpr,int(a["alert"].sum()),len(a),int(c["alert"].sum()),len(c)

def perchunk(rows,win="5s"):
    w=rows[(rows["window"]==win)&(rows["phase"]=="attack")]
    g=w.groupby("chunk_id")["alert"].agg(["sum","count"])
    return 100*g["sum"]/g["count"]

# ---- Figure 4.1: ablation, per-chunk mean +/- SD
def f1(df):
    means,sds,fprs=[],[],[]
    for m in MODES:
        pc=perchunk(mode_rows(df,m)); means.append(pc.mean()); sds.append(pc.std())
        fprs.append(pooled(mode_rows(df,m))[1])
    labs=[LABEL[m] for m in MODES]
    fig,(a1,a2)=plt.subplots(1,2,figsize=(9,4))
    a1.bar(labs,means,yerr=sds,capsize=4,color=BAR,width=0.6,error_kw=dict(ecolor="#555",lw=1))
    a1.axhline(95,color=ACCENT,ls="--",lw=1,label="DR target 95%")
    a1.set_ylabel("Detection Rate (%)"); a1.set_ylim(0,110); a1.set_title("(a) Per-chunk DR (mean +/- SD)")
    a1.legend(fontsize=9,loc="lower left")
    a2.bar(labs,fprs,color=BAR2,width=0.6)
    a2.axhline(0.97,color=ACCENT,ls="--",lw=1,label="FPR target 0.97%")
    a2.set_ylabel("False Positive Rate (%)"); a2.set_title("(b) FPR by mode")
    a2.legend(fontsize=9,loc="upper left")
    for ax in (a1,a2):
        ax.set_axisbelow(True); plt.setp(ax.get_xticklabels(),rotation=20,ha="right",fontsize=9)
    for r,v in zip(a2.patches,fprs): a2.text(r.get_x()+r.get_width()/2,v+max(fprs)*0.02,f"{v:.2f}",ha="center",fontsize=9)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_1.png")); plt.close(fig); print("  figure_4_1.png")

# ---- Figure 4.2: OAKF threshold vs frozen fixed threshold (entropy, chunk 01)
def f2(df):
    full=dedup_full(df); d=full[(full["chunk_id"]==1)&(full["window"]=="5s")].sort_values("elapsed_s")
    if d.empty: print("  WARN no chunk 01 FULL data, skip figure_4_2"); return
    cal=d[d["phase"]=="calibration"]["entropy"].dropna()
    calnz=cal[cal>0]
    fixed=calnz.mean()-3*calnz.std() if len(calnz) else cal.mean()
    print(f"  f2: fixed threshold = {fixed:.4f} bits")
    fig,ax=plt.subplots(figsize=(9,4.2))
    ax.plot(d.elapsed_s,d.entropy,color="#333",lw=1,label="Entropy signal")
    ax.plot(d.elapsed_s,d.entropy_thresh,color=BAR,lw=1.4,label="OAKF threshold (adaptive)")
    ax.axhline(fixed,color=ACCENT,ls="--",lw=1.4,label="Fixed threshold (mean-3SD, frozen)")
    ax.set_xlabel("Elapsed time (s)"); ax.set_ylabel("Shannon entropy (bits)")
    ax.set_title("OAKF adaptive vs fixed entropy threshold (Chunk 01, FULL)")
    ax.legend(fontsize=9); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_2.png")); plt.close(fig); print("  figure_4_2.png")

# ---- Figure 4.3: per-window DR and FPR (FULL)
def f3(df):
    full=dedup_full(df); wins=["5s","30s","120s"]; drs,fprs=[],[]
    for w in wins: r=pooled(full,w); drs.append(r[0]); fprs.append(r[1])
    x=range(len(wins)); fig,ax=plt.subplots(figsize=(7,4.2)); wb=0.38
    b1=ax.bar([i-wb/2 for i in x],drs,wb,color=BAR,label="Detection Rate")
    b2=ax.bar([i+wb/2 for i in x],fprs,wb,color=BAR2,label="False Positive Rate")
    ax.set_xticks(list(x)); ax.set_xticklabels(wins); ax.set_xlabel("Observation window")
    ax.set_ylabel("Rate (%)"); ax.set_ylim(0,110); ax.set_title("DR and FPR by window (FULL)")
    ax.legend(fontsize=9); ax.set_axisbelow(True)
    for bars,vals in ((b1,drs),(b2,fprs)):
        for r,v in zip(bars,vals): ax.text(r.get_x()+r.get_width()/2,v+1.5,f"{v:.1f}",ha="center",fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_3.png")); plt.close(fig); print("  figure_4_3.png")

# ---- Figure 4.4: per-chunk DR (FULL, 5s)
def f4(df):
    pc=perchunk(dedup_full(df)).sort_index(); ch=[str(int(c)) for c in pc.index]; v=pc.tolist()
    col=lambda x: BAR if x>=99.9 else ("#7a9cc6" if x>=95 else BAR2)
    fig,ax=plt.subplots(figsize=(10,4))
    ax.bar(ch,v,color=[col(x) for x in v],width=0.7)
    ax.axhline(95,color=ACCENT,ls="--",lw=1,label="DR target 95%")
    ax.set_xlabel("Attack chunk"); ax.set_ylabel("Detection Rate (%)"); ax.set_ylim(80,102)
    ax.set_title("Per-chunk Detection Rate (FULL, 5s window)"); ax.legend(fontsize=9,loc="lower left")
    ax.set_axisbelow(True); plt.setp(ax.get_xticklabels(),fontsize=8)
    ax.text(0.99,0.04,f"mean={sum(v)/len(v):.1f}%  range {min(v):.1f}-{max(v):.1f}%",
        transform=ax.transAxes,ha="right",fontsize=9,bbox=dict(boxstyle="round,pad=0.3",fc="white",ec="#ccc"))
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_4.png")); plt.close(fig); print("  figure_4_4.png")

# ---- Figure 4.5: signal trace (chunk 01, FULL, 5s)
def f5(df):
    full=dedup_full(df); d=full[(full["chunk_id"]==1)&(full["window"]=="5s")].sort_values("elapsed_s")
    if d.empty: print("  WARN no chunk 01 FULL data, skip figure_4_5"); return
    fig,(a1,a2)=plt.subplots(2,1,sharex=True,figsize=(9,6))
    a1.plot(d.elapsed_s,d.entropy,color=BAR,lw=1); a1.plot(d.elapsed_s,d.entropy_thresh,"--",color=ACCENT,lw=1)
    a1.set_ylabel("Entropy (bits)"); a1.legend(["entropy","OAKF threshold"],fontsize=8)
    a2.plot(d.elapsed_s,d.synack_ratio,color=BAR,lw=1); a2.plot(d.elapsed_s,d.synack_thresh,"--",color=ACCENT,lw=1)
    a2.set_yscale("log"); a2.set_ylabel("SYN/ACK ratio (log)"); a2.set_xlabel("Elapsed time (s)")
    a2.legend(["ratio","OAKF threshold"],fontsize=8)
    for ax in (a1,a2):
        for ph,clr in (("calibration","#f0f0f0"),("attack","#fbe4e4")):
            seg=d[d["phase"]==ph]
            if not seg.empty: ax.axvspan(seg.elapsed_s.min(),seg.elapsed_s.max(),color=clr,zorder=0)
    for t in d[d["alert"]==1].elapsed_s: a1.axvline(t,color="#888",lw=0.5,alpha=0.5)
    a1.set_title("Representative signal trace (Chunk 01, FULL, 5s)")
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_5.png")); plt.close(fig); print("  figure_4_5.png")

# ---- Figure 4.6: FPR across modes, log scale, with literature reference lines
def f6(df):
    fprs=[pooled(mode_rows(df,m))[1] for m in MODES]; labs=[LABEL[m] for m in MODES]
    disp=[max(x,0.001) for x in fprs]
    fig,ax=plt.subplots(figsize=(8,4.2))
    ax.bar(labs,disp,color=BAR,width=0.6)
    ax.set_yscale("log"); ax.set_ylabel("False Positive Rate (%, log)")
    ax.axhline(0.97,color=ACCENT,ls="--",lw=1,label="Aladaileh 2022 floor 0.97%")
    ax.axhline(4.0,color="#888",ls=":",lw=1,label="Zhang 2024 ~3-5%")
    ax.set_title("False positive rate by mode (log scale)"); ax.legend(fontsize=9)
    for r,v in zip(ax.patches,fprs): ax.text(r.get_x()+r.get_width()/2,max(v,0.001)*1.1,f"{v:.3f}%",ha="center",fontsize=8)
    plt.setp(ax.get_xticklabels(),rotation=20,ha="right",fontsize=9)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,"figure_4_6.png")); plt.close(fig); print("  figure_4_6.png")

def summary(df):
    print("\n========== SUMMARY (paste this back) ==========")
    print("[Table 4.2] per mode, 5s window:")
    for m in MODES:
        dr,fpr,dn,da,fn,fc=pooled(mode_rows(df,m))
        pc=perchunk(mode_rows(df,m))
        print(f"  {m:16s} DR(pooled)={dr:5.1f}% {dn}/{da}  DR(perchunk mean+/-SD)={pc.mean():.1f}+/-{pc.std():.1f}  FPR={fpr:.3f}% {fn}/{fc}")
    print("[Table 4.3] FULL per window:")
    for w in ["5s","30s","120s"]:
        dr,fpr,dn,da,fn,fc=pooled(dedup_full(df),w)
        print(f"  {w:5s} DR={dr:5.1f}% {dn}/{da}  FPR={fpr:.3f}% {fn}/{fc}")
    print("===============================================\n")

if __name__=="__main__":
    df=load(); print(f"Loaded {len(df):,} rows")
    f1(df); f2(df); f3(df); f4(df); f5(df); f6(df); summary(df)
    print(f"Done -> {OUT}")
