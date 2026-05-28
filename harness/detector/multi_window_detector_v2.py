#!/usr/bin/env python3
"""
Multi-window DDoS detector — experiment harness version (v2).

Changes over v1:
  - Per-run CSV output: logs/run_<RUN_ID>_chunk_<CHUNK_ID>_<MODE>.csv
  - Phase column:       "calibration" | "attack" | "post"
  - Ablation modes:     FULL | NO_MULTI_WINDOW | NO_DUAL_MECH | FIXED_THRESHOLD
  - Environment vars:   RUN_ID, CHUNK_ID, ABLATION_MODE, CALIBRATION_SECS

Ablation mode semantics
-----------------------
FULL            All three windows + dual-mechanism confirmation (proposed system).
NO_MULTI_WINDOW Only the 5 s window; 30 s and 120 s are disabled.
NO_DUAL_MECH    Three windows; alert fires on M1 alone (entropy OR revisit),
                M2 (synack) is computed but not required.
FIXED_THRESHOLD Three windows + dual mechanism, but OAKF thresholds are frozen
                at the end of the calibration phase (mean + k*SD from
                calibration observations); no further adaptation during attack.

Detection metric labelling
--------------------------
A window cycle is labelled by the *end* timestamp of that cycle:
  phase == "calibration"  if end_time < calibration_end
  phase == "attack"       if calibration_end <= end_time < attack_end
  phase == "post"         otherwise
compute_metrics.py uses these labels to derive DR and FPR.

The 120 s window will typically complete only once during calibration
(at t=120) and once during the mixed zone (t=240, spanning calibration
tail + full attack). That second cycle is labelled "attack" because the
attack is active when the cycle fires — the signal values will reflect the
blended traffic, which is by design for slow-DDoS detection evaluation.
"""

import csv
import math
import os
import statistics
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oakf import OAKF

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, tcp
from ryu.lib import hub


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TCP_SYN = 0x02
TCP_ACK = 0x10
SYNACK_RATIO_CAP = 10000.0

SIGNALS = ("entropy", "revisit_ratio", "synack_ratio")

OAKF_PARAMS = {
    "entropy":        {"process_noise": 1e-3, "measurement_noise": 0.5,  "deviation_multiplier": 3.0, "warmup_cycles": 3},
    "revisit_ratio":  {"process_noise": 1e-2, "measurement_noise": 10.0, "deviation_multiplier": 3.0, "warmup_cycles": 3},
    "synack_ratio":   {"process_noise": 1e-2, "measurement_noise": 5.0,  "deviation_multiplier": 3.0, "warmup_cycles": 3},
}

# Fixed-threshold fallback: k sigmas over the calibration sample mean.
# Used only in FIXED_THRESHOLD mode.
FIXED_THRESHOLD_K = 3.0

VALID_MODES = {"FULL", "NO_MULTI_WINDOW", "NO_DUAL_MECH", "FIXED_THRESHOLD"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default).strip()


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, str(default)))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Per-window state
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Fixed-threshold helper (FIXED_THRESHOLD ablation)
# ---------------------------------------------------------------------------

class FixedThresholdTracker:
    """
    Collects signal samples during calibration; computes a frozen threshold
    (mean + k*SD) at the end of that phase. During attack, uses that value.
    Requires at least 2 samples to compute SD; falls back to mean*2 if not.
    """

    def __init__(self, k: float = FIXED_THRESHOLD_K):
        self.k = k
        self.samples: list = []
        self.frozen = False
        self.threshold: float = 0.0
        self.mean: float = 0.0

    def add_sample(self, value: float):
        """Call during calibration phase only."""
        self.samples.append(value)

    def freeze(self):
        """Call at calibration end. Computes and locks the threshold."""
        if len(self.samples) < 2:
            # Degenerate — not enough calibration cycles.
            self.mean = self.samples[0] if self.samples else 0.0
            self.threshold = self.mean * 2.0
        else:
            self.mean = statistics.mean(self.samples)
            sd = statistics.stdev(self.samples)
            self.threshold = self.mean + self.k * sd
        self.frozen = True

    def is_anomaly(self, value: float) -> tuple:
        """Returns (is_anom, threshold). Valid only after freeze()."""
        if not self.frozen:
            return False, 0.0
        return abs(value - self.mean) > self.threshold, self.threshold


# ---------------------------------------------------------------------------
# Main Ryu application
# ---------------------------------------------------------------------------

class MultiWindowDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # -- Run parameters from environment --
        self.run_id          = _env_str("RUN_ID", "test")
        self.chunk_id        = _env_str("CHUNK_ID", "0")
        self.ablation_mode   = _env_str("ABLATION_MODE", "FULL").upper()
        self.calib_secs      = _env_float("CALIBRATION_SECS", 150.0)
        # Attack duration is chunk duration (~84 s for 418 853 pkts at 5 000 pps).
        # We record for 30 s post-attack to catch any late 30 s / 120 s window
        # cycles. run_one_chunk.sh will kill us after attack finishes.
        self.attack_secs     = _env_float("ATTACK_SECS", 90.0)

        if self.ablation_mode not in VALID_MODES:
            self.logger.warning(
                "Unknown ABLATION_MODE '%s'; defaulting to FULL.", self.ablation_mode
            )
            self.ablation_mode = "FULL"

        self.t_start         = time.time()
        self.calib_end       = self.t_start + self.calib_secs
        self.attack_end      = self.calib_end + self.attack_secs
        self.calib_frozen    = False   # FIXED_THRESHOLD: has freeze() been called?
        self.datapaths       = {}      # dpid → datapath, populated by switch_features_handler

        # -- Window configuration --
        if self.ablation_mode == "NO_MULTI_WINDOW":
            window_specs = [("5s", 5)]
        else:
            window_specs = [("5s", 5), ("30s", 30), ("120s", 120)]

        self.windows = {name: WindowState(name, dur) for name, dur in window_specs}

        # -- OAKF instances (9 for FULL/NO_DUAL_MECH, 3 for NO_MULTI_WINDOW) --
        self.oakfs = {
            wname: {sig: OAKF(**OAKF_PARAMS[sig]) for sig in SIGNALS}
            for wname in self.windows
        }

        # -- Fixed-threshold trackers (FIXED_THRESHOLD mode only) --
        self.ft = {
            wname: {sig: FixedThresholdTracker() for sig in SIGNALS}
            for wname in self.windows
        }

        self.cycle_count = defaultdict(int)
        self.alert_count = defaultdict(int)

        # -- CSV output --
        log_dir = os.environ.get(
            "LOG_DIR",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "logs"))
        )
        os.makedirs(log_dir, exist_ok=True)
        csv_name = f"run_{self.run_id}_chunk_{self.chunk_id}_{self.ablation_mode}.csv"
        self.csv_path = os.path.join(log_dir, csv_name)
        self.csv_fh = open(self.csv_path, "w", newline="")
        self.csv_writer = csv.writer(self.csv_fh)
        self.csv_writer.writerow([
            "timestamp", "elapsed_s", "phase", "window",
            "packets", "unique_ips", "syn", "synack",
            "entropy",      "entropy_thresh",      "entropy_anom",
            "revisit",      "revisit_thresh",      "revisit_anom",
            "synack_ratio", "synack_thresh",        "synack_anom",
            "mech1", "mech2", "alert",
            "proc_time_ms",
            "run_id", "chunk_id", "ablation_mode",
        ])
        self.csv_fh.flush()

        self.logger.info(
            "MultiWindowDetectorV2 | run=%s chunk=%s mode=%s "
            "calib=%.0fs windows=%s",
            self.run_id, self.chunk_id, self.ablation_mode,
            self.calib_secs, list(self.windows.keys())
        )

        for name in self.windows:
            hub.spawn(self._window_monitor, name)

        # Spawn greenlet that installs the SYN-ACK dataplane DROP rule at calib_end.
        # Runs unconditionally across all ablation modes.
        hub.spawn(self._install_synack_drop_at_calib_end)

        # Spawn a watchdog that freezes FIXED_THRESHOLD trackers at calib end.
        if self.ablation_mode == "FIXED_THRESHOLD":
            hub.spawn(self._freeze_watchdog)

    # -----------------------------------------------------------------------
    # Phase helpers
    # -----------------------------------------------------------------------

    def _current_phase(self) -> str:
        now = time.time()
        if now < self.calib_end:
            return "calibration"
        if now < self.attack_end:
            return "attack"
        return "post"

    # -----------------------------------------------------------------------
    # FIXED_THRESHOLD freeze watchdog
    # -----------------------------------------------------------------------

    def _freeze_watchdog(self):
        """Sleep until calibration ends, then freeze all fixed trackers."""
        remaining = self.calib_end - time.time()
        if remaining > 0:
            hub.sleep(remaining)
        for wname, sigs in self.ft.items():
            for sig_name, tracker in sigs.items():
                tracker.freeze()
                self.logger.info(
                    "FIXED_THRESHOLD freeze | window=%s signal=%s "
                    "mean=%.4f thresh=%.4f (n=%d samples)",
                    wname, sig_name,
                    tracker.mean, tracker.threshold, len(tracker.samples)
                )
        self.calib_frozen = True
        self.logger.info("FIXED_THRESHOLD: all trackers frozen.")

    # -----------------------------------------------------------------------
    # SYN-ACK dataplane DROP rule (installed at calibration end)
    # -----------------------------------------------------------------------

    def _install_synack_drop_at_calib_end(self):
        """
        Sleep until calibration ends, then push a priority=200 DROP rule for
        SYN+ACK packets to every connected datapath.

        Priority 200 beats both the table-miss rule (priority=0) installed by
        switch_features_handler and any ovs-ofctl rule at priority=100 applied
        by experiment.py — whichever arrives first, this one wins.

        Installing via the OF channel guarantees the rule lands on exactly the
        datapaths Ryu is managing, with no dependency on correct switch names
        or timing from an external shell command.
        """
        remaining = self.calib_end - time.time()
        if remaining > 0:
            hub.sleep(remaining)

        n = 0
        for dpid, dp in list(self.datapaths.items()):
            ofp    = dp.ofproto
            parser = dp.ofproto_parser
            match  = parser.OFPMatch(
                eth_type=0x0800,        # IPv4
                ip_proto=6,             # TCP
                tcp_flags=(0x012, 0x012),  # SYN (0x002) + ACK (0x010), masked
            )
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_ADD,
                priority=200,
                match=match,
                instructions=[],        # empty instructions list = DROP
            )
            dp.send_msg(mod)
            self.logger.info("Installed SYN-ACK DROP rule | dpid=%016x priority=200", dpid)
            n += 1

        self.logger.info(
            "SYN-ACK DROP rules installed on %d datapath(s). "
            "synack_ratio will be 10000 from next attack cycle.",
            n,
        )

    # -----------------------------------------------------------------------
    # Per-window monitor loop
    # -----------------------------------------------------------------------

    def _window_monitor(self, window_name: str):
        win = self.windows[window_name]
        while True:
            hub.sleep(win.duration_s)

            t0 = time.time()
            elapsed = t0 - self.t_start
            phase = self._current_phase()
            sig = win.compute_signals()

            # -- Compute anomaly flags according to ablation mode --
            results = {}
            for sig_name in SIGNALS:
                raw_val = sig[sig_name]

                if self.ablation_mode == "FIXED_THRESHOLD":
                    if phase == "calibration":
                        # Feed calibration samples; OAKF still runs for
                        # threshold initialisation, but we also collect
                        # values for the fixed tracker.
                        self.ft[window_name][sig_name].add_sample(raw_val)
                        _, resid, thresh = self.oakfs[window_name][sig_name].update(raw_val)
                        is_anom = False   # No alerts during calibration in FT mode.
                    else:
                        # Use frozen threshold.
                        is_anom, thresh = self.ft[window_name][sig_name].is_anomaly(raw_val)
                        resid = raw_val - self.ft[window_name][sig_name].mean
                else:
                    is_anom, resid, thresh = self.oakfs[window_name][sig_name].update(raw_val)

                results[sig_name] = {
                    "value": raw_val,
                    "threshold": thresh,
                    "anomaly": is_anom,
                    "residual": resid,
                }

            # -- Mechanism logic --
            mech1 = (
                results["entropy"]["anomaly"] or results["revisit_ratio"]["anomaly"]
            )
            mech2 = results["synack_ratio"]["anomaly"]

            if self.ablation_mode == "NO_DUAL_MECH":
                alert = mech1          # M2 not required
            else:
                alert = mech1 and mech2

            proc_time_ms = (time.time() - t0) * 1000

            self.cycle_count[window_name] += 1
            if alert:
                self.alert_count[window_name] += 1

            self.logger.info(
                "[%s] phase=%-13s H=%.3f(%s) rev=%.2f(%s) sa=%.2f(%s) "
                "| M1=%s M2=%s ALERT=%s | %.2fms",
                window_name, phase,
                results["entropy"]["value"],       "Y" if results["entropy"]["anomaly"]       else ".",
                results["revisit_ratio"]["value"], "Y" if results["revisit_ratio"]["anomaly"] else ".",
                results["synack_ratio"]["value"],  "Y" if results["synack_ratio"]["anomaly"]  else ".",
                "Y" if mech1 else ".", "Y" if mech2 else ".",
                "YES" if alert else "no",
                proc_time_ms,
            )

            self.csv_writer.writerow([
                f"{t0:.3f}", f"{elapsed:.2f}", phase, window_name,
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
                self.run_id, self.chunk_id, self.ablation_mode,
            ])
            self.csv_fh.flush()
            win.reset()

    # -----------------------------------------------------------------------
    # OpenFlow handlers (unchanged from v1)
    # -----------------------------------------------------------------------

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
        self.datapaths[dp.id] = dp
        self.logger.info("Default flow installed on dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip  = pkt.get_protocol(ipv4.ipv4)
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
            in_port=msg.match["in_port"], actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        )
        dp.send_msg(out)
