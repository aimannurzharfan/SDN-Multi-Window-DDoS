# sdn-thesis — Codebase Guide

Multi-timescale TCP SYN flood detector for SDN. Ryu (OpenFlow 1.3) on Mininet.
OAKF adaptive thresholds. Target: DR ≥ 95%, FPR < 0.97%.

## Thesis argument
Three windows (5s/30s/120s) × three signals (entropy, IP revisit rate, SYN/ACK ratio)
= 9 OAKF instances. Alert = M1 AND M2. M1 = entropy_anom OR revisit_anom.
M2 = synack_ratio_anom. Lower FPR than single-window fixed-threshold,
without ML inference overhead on the Ryu controller.

## Key files
  harness/detector/multi_window_detector_v2.py  Ryu app, OAKF, WindowState, CSV, ablation
  harness/detector/oakf.py                      OAKF (skips zero; seeds on first non-zero)
  harness/scripts/experiment.py                 full trial lifecycle
  harness/traffic/legit_traffic_gen.py          raw-socket calibration traffic (20 pps, 20 IPs)
  harness/scripts/compute_metrics.py            aggregates CSV → DR/FPR/proc-time
  topology/tree_5sw_20h.py                      5 switches, 20 hosts (h1-h15 legit, h16 attacker)
  chunks/chunk_00000.pcap … chunk_00029.pcap    CIC-DDoS2019, ~418k SYN/chunk, ~84s each

## Running a trial
  source ~/ryu-env/bin/activate
  CALIBRATION_SECS=150 ATTACK_SECS=90 sudo -E python3 \
    ~/sdn-thesis/harness/scripts/experiment.py <chunk_id> <MODE> <run_id>
  Modes: FULL | NO_MULTI_WINDOW | NO_DUAL_MECH | FIXED_THRESHOLD

## DR/FPR check
  awk -F',' 'NR>1 && $4=="5s" {
    att+=($3=="attack"); det+=($3=="attack" && $20==1);
    cal+=($3=="calibration"); fp+=($3=="calibration" && $20==1)
  } END {printf "DR=%d/%d=%.1f%%  FPR=%d/%d=%.1f%%\n",det,att,100*det/att,fp,cal,100*fp/cal}' \
    ~/sdn-thesis/logs/<csv>

## Phase timing (startup_offset = 70)
  calib_secs = 150 + 70 = 220s. calib_end = ryu_start + 220.
  12s Ryu startup + 15s OF handshakes + 5s Mininet overhead
  + 8s pre-attack cleanup + 30s Ryu queue drain = 70s.

## Calibration traffic design
  legit_traffic_gen.py at 20 pps (10 SYN + 10 SYN-ACK/s) from 20 IPs.
  No iperf3 — iperf3 data packets create ~187,500 Ryu queue events,
  requiring 130s+ to drain and contaminating the first attack cycles.
  At 20 pps: backlog = ~7,500 events, drains in ~7.5s (within 30s drain window).

## SYN-ACK contamination defence (all layers)
  1. tcp_synack_retries=0 on h1-h15 (kernel)
  2. iptables INPUT/OUTPUT rules on h1-h15 (topology start)
  3. iptables -I OUTPUT 1 block all SYN-ACK (pre-attack cleanup)
  4. ovs-ofctl priority=100 DROP on s1-s5 (pre-attack cleanup)
  5. OFPFlowMod priority=200 DROP via OF channel on all datapaths (calib_end)
  6. 30s drain period after step 4 to flush Ryu packet_in queue backlog

## OAKF parameters
  signal         Q      R     k    warmup
  entropy        1e-3   0.5   3.0  3 cycles
  revisit_ratio  1e-2   10.0  3.0  3 cycles
  synack_ratio   1e-2   5.0   3.0  3 cycles
  SYNACK_RATIO_CAP = 10000.0

## Ryu binary: /usr/bin/ryu-manager (NOT ~/ryu-env which is empty)
