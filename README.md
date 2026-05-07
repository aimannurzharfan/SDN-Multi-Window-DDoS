# Multi-Window Entropy DDoS Detection on Ryu SDN

Implementation of a multi-timescale Shannon entropy detection system with
Online Adaptive Kalman Filter (OAKF) thresholds for TCP SYN flood detection
on the Ryu SDN controller.

## Components
- Custom Mininet topology: 5 switches, 20 hosts (15 legitimate, 5 attackers)
- Three observation windows: 5s, 30s, 120s
- Detection signals: Shannon entropy, IP Revisit Ratio, SYN/ACK ratio
- Adaptive thresholds via OAKF on each signal-window pair
- Evaluation: 30-chunk replay of CIC-DDoS2019 PCAP-03-11 (SYN flood subset)

## Environment
See `docs/environment_versions.txt`.
