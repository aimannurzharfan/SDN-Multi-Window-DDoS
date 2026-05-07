# Project Context for Claude Code

## What this project is
A thesis-grade implementation of a multi-window entropy DDoS detector running
on a Ryu SDN controller, evaluated against CIC-DDoS2019 in a Mininet testbed.

## Stack
- Ubuntu 20.04 LTS in Oracle VirtualBox
- Python 3.8 in venv at ~/ryu-env
- Ryu 4.34 (OpenFlow 1.3)
- Mininet 2.3.0 with Open vSwitch
- tcpreplay, editcap for PCAP handling
- NumPy, pandas, matplotlib, filterpy for analysis

## Detector design (do not deviate without confirmation)
- Three observation windows: 5s, 30s, 120s
- Mechanism 1 (anomaly): bidirectional Shannon entropy deviation OR IP Revisit Ratio collapse
- Mechanism 2 (validation): TCP SYN/ACK ratio above OAKF threshold
- Alert condition: Mechanism 1 AND Mechanism 2 both fire in the same window
- 9 OAKF instances total: 3 metrics x 3 windows
- Reset all counters and OAKF state between simulation chunks

## Coding conventions
- Type hints on all function signatures
- Docstrings on all classes and public methods
- Use logging module, not print, for runtime output
- Wall-clock processing time per detection cycle is a measured metric: do not
  add unnecessary work inside Packet-In handlers
- Per-Packet-In handler operations must remain O(1)

## File layout
- topology/  Mininet topology Python scripts
- detector/  Ryu detector application
- scripts/   Simulation runner, chunking, aggregation
- results/   Per-chunk CSV outputs
- logs/      Ryu and Mininet runtime logs

## How to run things
- Activate venv: source ~/ryu-env/bin/activate
- Run detector: ryu-manager detector/multi_window_detector.py
- Start topology: sudo python3 topology/tree_5sw_20h.py
- Replay chunk: sudo tcpreplay -i <iface> --pps=5000 chunks/chunk_NNNNN.pcap

## Important constraints
- Do NOT upgrade Python past 3.8 in this venv (breaks Ryu)
- Do NOT upgrade eventlet past 0.30.2 (breaks Ryu imports)
- Do NOT commit PCAP files (too large; .gitignore handles this)
