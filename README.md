# BOUN Cross-Dataset Validation and Drift Experiment

Live validation of the multi-window SYN flood detector on the spoofed, multi-source BOUN DDoS dataset, and a controlled non-stationary baseline experiment. This branch extends the CIC-DDoS2019 detector on `main` to the spoofed source profile and to a drifting legitimate baseline. The detection logic is unchanged; only the traffic path and the analysis differ.

## What this branch adds
Live replay of the BOUN spoofed flood through Mininet and Ryu, with a dataplane forwarding rule that keeps established-connection traffic off the controller so only new flows reach it. And a controlled drift experiment: a rising legitimate baseline with attacks injected across it, comparing the adaptive threshold against a fixed threshold swept over its full multiplier range.

## Key scripts
- `build_boun_pcap.py`: reconstructs a replayable PCAP from the BOUN CSV.
- `experiment_boun.py`: live BOUN replay harness, forwarding offload and CPU sampling.
- `recompute_boun_labels.py`: pulse-aware window labelling.
- `analyze_boun_batch.py`, `run_boun_batch.py`: batch analysis and driver.
- `drift_experiment.py`, `drift_live_gen.py`, `experiment_drift_live.py`: drift generation and the live drift harness.
- `fixed_sweep.py`, `analyze_drift_live.py`, `run_drift_live_batch.sh`: the fixed-threshold sweep, analysis, and batch driver.

## Running
Build the capture with `build_boun_pcap.py`, then replay it live with `experiment_boun.py`. Run the drift experiment with `run_drift_live_batch.sh`.

## Relation to main
The detector and OAKF are shared with `main`. This branch changes only the traffic path and the analysis, not the detection.
