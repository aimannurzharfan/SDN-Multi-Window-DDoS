# Multi-Window SYN Flood Detection for SDN

A lightweight, controller-resident detector for TCP SYN floods in Software-Defined Networking. It runs on the Ryu controller and uses no machine-learning inference.

## Approach
Three concurrent observation windows (5, 30, and 120 seconds) feed two confirmation mechanisms. Mechanism 1 reads source behaviour through bidirectional Shannon entropy and the IP revisit rate. Mechanism 2 reads protocol behaviour through the SYN/ACK ratio. An alert requires both to agree in the same window. An Online Adaptive Kalman Filter sets each threshold from the live baseline, so no threshold is hand-tuned.

## Layout
- `multi_window_detector_v2.py` — Ryu detection application (windows, OAKF, dual-mechanism, ablation modes).
- `oakf.py` — Online Adaptive Kalman Filter.
- `tree_5sw_20h.py` — Mininet topology, five switches and twenty hosts.
- `experiment.py` — CIC-DDoS2019 trial lifecycle.
- `compute_metrics.py` — aggregates detection rate, false positive rate, and processing time.
- `chunks/` — CIC-DDoS2019 SYN-flood replay chunks.

## Running a trial
Activate the Ryu virtualenv, then run `experiment.py <chunk_id> <MODE> <run_id>`, where MODE is one of FULL, NO_MULTI_WINDOW, NO_DUAL_MECH, FIXED_THRESHOLD. Aggregate with `compute_metrics.py`.

## Datasets
This branch covers the single-source CIC-DDoS2019 flood. The spoofed multi-source cross-dataset validation on the BOUN dataset and the non-stationary drift experiment are on the `boun` branch.
