#!/usr/bin/env python3
"""
Multi-window DDoS detector for Ryu SDN controller.

- Installs a default flow rule on each switch that sends unknown packets
  to the controller.
- Handles PacketIn events and logs every TCP packet.
- Floods every packet so the network stays usable while we develop.

Subsequent stages will add per-window counters, entropy/IP-revisit/SYN-ACK
signals, OAKF thresholds, and the dual-mechanism alert logic.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp


class MultiWindowDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pkt_count = 0
        self.logger.info("MultiWindowDetector initialised (Stage 3 skeleton)")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a default rule: send unknown packets to the controller."""
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

        self.pkt_count += 1

        if ip and tcp_pkt:
            self.logger.info(
                "PKT #%d  src=%s dst=%s  flags=0x%02x",
                self.pkt_count, ip.src, ip.dst, tcp_pkt.bits,
            )

        # Flood the packet so the network keeps working while we develop
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