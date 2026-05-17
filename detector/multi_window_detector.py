#!/usr/bin/env python3
"""
Multi-window DDoS detector for Ryu SDN controller.

computes three detection signals per window boundary.

Signals:
  1. Shannon entropy on source IP distribution (bits)
  2. IP Revisit Ratio = total_packets / unique_source_ips
  3. SYN/ACK Ratio    = syn_count / synack_count

Per Chapter 3 design:
  - Mechanism 1 (anomaly):    entropy deviation OR revisit ratio collapse
  - Mechanism 2 (validation): SYN/ACK ratio anomaly
  - Alert fires only when BOTH mechanisms fire in the same window
  (OAKF adaptive thresholds added in Stage 6; this stage just emits values.)
"""

import math
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp
from ryu.lib import hub


# TCP flag bits
TCP_SYN = 0x02
TCP_ACK = 0x10

# Cap synack_ratio at this value when synack_count == 0, to keep it finite
# (an infinity in logs and Kalman filters is just trouble for no benefit).
SYNACK_RATIO_CAP = 10000.0


def shannon_entropy(counts: dict) -> float:
    """
    Compute Shannon entropy in bits over a {item: count} distribution.

    H(X) = -sum( p_i * log2(p_i) )   for all i with count > 0
    """
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


class WindowState:
    """Per-window rolling state."""

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
        """Compute entropy, IP Revisit Ratio, SYN/ACK ratio."""
        unique_ips = len(self.src_ip_counts)

        entropy = shannon_entropy(self.src_ip_counts)

        if unique_ips > 0:
            revisit_ratio = self.packet_count / unique_ips
        else:
            revisit_ratio = 0.0

        if self.synack_count > 0:
            synack_ratio = self.syn_count / self.synack_count
        elif self.syn_count > 0:
            synack_ratio = SYNACK_RATIO_CAP
        else:
            synack_ratio = 0.0

        return {
            "window": self.name,
            "elapsed_s": round(time.time() - self.start_time, 2),
            "packets": self.packet_count,
            "unique_ips": unique_ips,
            "syn": self.syn_count,
            "synack": self.synack_count,
            "entropy": entropy,
            "revisit_ratio": revisit_ratio,
            "synack_ratio": synack_ratio,
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
        self.logger.info(
            "MultiWindowDetector initialised (Stage 5) "
            "with 3 signals x 3 windows = 9 measurements per cycle"
        )

        for name in self.windows:
            hub.spawn(self._window_monitor, name)

    def _window_monitor(self, window_name: str):
        win = self.windows[window_name]
        while True:
            hub.sleep(win.duration_s)
            sig = win.compute_signals()
            self.logger.info(
                "[%-4s] pkts=%-7d uniq=%-6d  "
                "H=%.3f  revisit=%.2f  synack_ratio=%.2f",
                sig["window"], sig["packets"], sig["unique_ips"],
                sig["entropy"], sig["revisit_ratio"], sig["synack_ratio"],
            )
            win.reset()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0,
                                match=match, instructions=inst)
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
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        )
        dp.send_msg(out)