#!/usr/bin/env python3
"""
Multi-window DDoS detector for Ryu SDN controller.

Stage 6: complete detector with OAKF adaptive thresholds and the
dual-mechanism alert logic from Chapter 3.

Architecture:
  - 3 observation windows:  5s, 30s, 120s
  - 3 detection signals:    Shannon entropy, IP revisit ratio, SYN/ACK ratio
  - 9 OAKF instances:       1 per signal x window pair
  - Mechanism 1 (anomaly):    entropy_anom OR revisit_anom
  - Mechanism 2 (validation): synack_anom
  - ALERT fires only when M1 AND M2 both fire in the same window
"""

import csv
import math
import os
import sys
import time
from collections import defaultdict

# Allow importing oakf.py from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oakf import OAKF

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp
from ryu.lib import hub


TCP_SYN = 0x02
TCP_ACK = 0x10
SYNACK_RATIO_CAP = 10000.0

SIGNALS = ("entropy", "revisit_ratio", "synack_ratio")

# Initial OAKF parameters. These will appear in Table 3.3 of Chapter 3.
# Tuned conservatively: low Q (slow baseline drift), R sized to the
# typical magnitude of each signal so 3-sigma is meaningful.
OAKF_PARAMS = {
    "entropy":       {"process_noise": 1e-3, "measurement_noise": 0.5,  "deviation_multiplier": 3.0, "warmup_cycles": 3},
    "revisit_ratio": {"process_noise": 1e-2, "measurement_noise": 10.0, "deviation_multiplier": 3.0, "warmup_cycles": 3},
    "synack_ratio":  {"process_noise": 1e-2, "measurement_noise": 5.0,  "deviation_multiplier": 3.0, "warmup_cycles": 3},
}

LOG_DIR = os.path.expanduser("~/sdn-thesis/logs")
CSV_PATH = os.path.join(LOG_DIR, "detector_signals.csv")


def shannon_entropy(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


class WindowState:
    def __init__(self, name: str, duration_s: int):
        self.name = name
        self.duration_s = duration_s
        self.reset()

    def reset(self):
        self.packet_count = 0
        self.syn_count = 0
        self.synack_count = 0
        self.src_ip_counts = defaultdict(int)
        self.start_time = time.time()

    def update(self, src_ip: str, tcp_flags: int):
        self.packet_count += 1
        self.src_ip_counts[src_ip] += 1
        is_syn = bool(tcp_flags & TCP_SYN)
        is_ack = bool(tcp_flags & TCP_ACK)
        if is_syn and not is_ack:
            self.syn_count += 1
        elif is_syn and is_ack:
            self.synack_count += 1

    def compute_signals(self) -> dict:
        unique_ips = len(self.src_ip_counts)
        entropy = shannon_entropy(self.src_ip_counts)
        revisit_ratio = (self.packet_count / unique_ips) if unique_ips > 0 else 0.0
        if self.synack_count > 0:
            synack_ratio = self.syn_count / self.synack_count
        elif self.syn_count > 0:
            synack_ratio = SYNACK_RATIO_CAP
        else:
            synack_ratio = 0.0
        return {
            "entropy": entropy,
            "revisit_ratio": revisit_ratio,
            "synack_ratio": synack_ratio,
            "packets": self.packet_count,
            "unique_ips": unique_ips,
            "syn": self.syn_count,
            "synack": self.synack_count,
        }


class MultiWindowDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.windows = {
            "5s":   WindowState("5s",   5),
            "30s":  WindowState("30s",  30),
            "120s": WindowState("120s", 120),
        }

        # 3 signals x 3 windows = 9 OAKFs
        self.oakfs = {
            wname: {sig: OAKF(**OAKF_PARAMS[sig]) for sig in SIGNALS}
            for wname in self.windows
        }

        self.cycle_count = defaultdict(int)
        self.alert_count = defaultdict(int)

        os.makedirs(LOG_DIR, exist_ok=True)
        self._init_csv()

        self.logger.info(
            "MultiWindowDetector initialised (Stage 6): "
            "9 OAKFs across {entropy, revisit, synack} x {5s, 30s, 120s}"
        )

        for name in self.windows:
            hub.spawn(self._window_monitor, name)

    def _init_csv(self):
        new_file = not os.path.exists(CSV_PATH)
        self.csv_fh = open(CSV_PATH, "a", newline="")
        self.csv_writer = csv.writer(self.csv_fh)
        if new_file:
            self.csv_writer.writerow([
                "timestamp", "window",
                "packets", "unique_ips", "syn", "synack",
                "entropy", "entropy_thresh", "entropy_anom",
                "revisit", "revisit_thresh", "revisit_anom",
                "synack_ratio", "synack_thresh", "synack_anom",
                "mech1", "mech2", "alert",
                "proc_time_ms",
            ])
            self.csv_fh.flush()

    def _window_monitor(self, window_name: str):
        win = self.windows[window_name]
        while True:
            hub.sleep(win.duration_s)

            t0 = time.time()
            sig = win.compute_signals()

            results = {}
            for sig_name in SIGNALS:
                is_anom, resid, thresh = self.oakfs[window_name][sig_name].update(sig[sig_name])
                results[sig_name] = {
                    "value": sig[sig_name],
                    "threshold": thresh,
                    "anomaly": is_anom,
                    "residual": resid,
                }

            # Dual-mechanism alert
            mech1 = results["entropy"]["anomaly"] or results["revisit_ratio"]["anomaly"]
            mech2 = results["synack_ratio"]["anomaly"]
            alert = mech1 and mech2

            proc_time_ms = (time.time() - t0) * 1000

            self.cycle_count[window_name] += 1
            if alert:
                self.alert_count[window_name] += 1

            self.logger.info(
                "[%-4s] H=%.3f(%s) rev=%.2f(%s) sa=%.2f(%s) | M1=%s M2=%s ALERT=%s | %.1fms",
                window_name,
                results["entropy"]["value"],       "Y" if results["entropy"]["anomaly"]       else ".",
                results["revisit_ratio"]["value"], "Y" if results["revisit_ratio"]["anomaly"] else ".",
                results["synack_ratio"]["value"],  "Y" if results["synack_ratio"]["anomaly"]  else ".",
                "Y" if mech1 else ".",
                "Y" if mech2 else ".",
                "YES" if alert else "no",
                proc_time_ms,
            )

            self.csv_writer.writerow([
                f"{time.time():.3f}", window_name,
                sig["packets"], sig["unique_ips"], sig["syn"], sig["synack"],
                f"{results['entropy']['value']:.4f}",
                f"{results['entropy']['threshold']:.4f}",
                int(results["entropy"]["anomaly"]),
                f"{results['revisit_ratio']['value']:.4f}",
                f"{results['revisit_ratio']['threshold']:.4f}",
                int(results["revisit_ratio"]["anomaly"]),
                f"{results['synack_ratio']['value']:.4f}",
                f"{results['synack_ratio']['threshold']:.4f}",
                int(results["synack_ratio"]["anomaly"]),
                int(mech1), int(mech2), int(alert),
                f"{proc_time_ms:.3f}",
            ])
            self.csv_fh.flush()

            win.reset()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("Default flow installed on switch dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if ip and tcp_pkt:
            for win in self.windows.values():
                win.update(ip.src, tcp_pkt.bits)

        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'], actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        )
        dp.send_msg(out)