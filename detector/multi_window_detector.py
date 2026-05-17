#!/usr/bin/env python3
"""
Multi-window DDoS detector for Ryu SDN controller.

per-window counters across 5s / 30s / 120s timescales.

Each window keeps its own rolling state:
  - total packet count
  - unique source IPs (hash set)
  - SYN count
  - SYN-ACK count

A background greenlet per window evaluates and resets the window
every duration_s seconds.
"""

import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp
from ryu.lib import hub


# TCP flag bits (from RFC 9293)
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


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

    def snapshot(self) -> dict:
        return {
            "window": self.name,
            "duration_s": self.duration_s,
            "elapsed_s": round(time.time() - self.start_time, 2),
            "packets": self.packet_count,
            "unique_ips": len(self.src_ip_counts),
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
        self.logger.info(
            "MultiWindowDetector initialised (Stage 4) with windows: %s",
            ", ".join(f"{w.name}={w.duration_s}s" for w in self.windows.values()),
        )

        # Launch one background greenlet per window
        for name in self.windows:
            hub.spawn(self._window_monitor, name)

    def _window_monitor(self, window_name: str):
        """
        Background greenlet that sleeps for the window duration, then
        snapshots and resets the window. Uses Ryu's hub (eventlet greenlets)
        rather than OS threads so it cooperates with the Ryu event loop.
        """
        win = self.windows[window_name]
        while True:
            hub.sleep(win.duration_s)
            snap = win.snapshot()
            self.logger.info(
                "[%-4s] pkts=%-7d uniq_ip=%-6d syn=%-7d synack=%-6d  elapsed=%.1fs",
                snap["window"], snap["packets"], snap["unique_ips"],
                snap["syn"], snap["synack"], snap["elapsed_s"],
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
            # Hot path: update all three windows in O(1) each
            for win in self.windows.values():
                win.update(ip.src, tcp_pkt.bits)

        # Flood the packet so the network keeps working
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