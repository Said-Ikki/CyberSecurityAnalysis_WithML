"""
POX controller component for the SDN DDoS lab.
Implements an L2 learning switch with packet-in logging, periodic flow-stats
polling, real-time ML inference scoring (ANN vs. 1D-CNN), and automated mitigation.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import pox.lib.packet as pkt
import time
import os
import sys

# Make sure the project directory and venv site-packages are importable from POX
for p in ['.', 'lab', '..', '/home/mininet/project', '/home/mininet/project/venv/lib/python3.8/site-packages']:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

import numpy as np

try:
    import scoring
    from eval_logger import EvalLogger
    SCORING_AVAILABLE = True
except Exception as e:
    SCORING_AVAILABLE = False
    core.getLogger("ddos_lab").warning("Scoring module not loaded: %s", e)

log = core.getLogger("ddos_lab")

PROTO_MAP = {
    pkt.ipv4.ICMP_PROTOCOL: "ICMP",
    pkt.ipv4.TCP_PROTOCOL:  "TCP",
    pkt.ipv4.UDP_PROTOCOL:  "UDP",
}

class LearningSwitch(object):
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent
        self.macToPort = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring unparsed packet")
            return

        # Inspect packet and log header fields
        ip_p = packet.find(pkt.ipv4)
        if ip_p:
            src_ip = str(ip_p.srcip)
            dst_ip = str(ip_p.dstip)
            proto_name = PROTO_MAP.get(ip_p.protocol, str(ip_p.protocol))
            length = len(packet.raw) if hasattr(packet, 'raw') and packet.raw else event.ofp.total_len

            src_port = None
            dst_port = None

            tcp_p = packet.find(pkt.tcp)
            udp_p = packet.find(pkt.udp)
            if tcp_p:
                src_port = tcp_p.srcport
                dst_port = tcp_p.dstport
            elif udp_p:
                src_port = udp_p.srcport
                dst_port = udp_p.dstport

            log.info("[PACKET-IN] IP %s:%s -> %s:%s | proto=%s | len=%d bytes | switch=%s",
                     src_ip, src_port if src_port is not None else "-",
                     dst_ip, dst_port if dst_port is not None else "-",
                     proto_name, length, dpid_to_str(event.dpid))
        else:
            log.info("[PACKET-IN] Non-IP %s -> %s | type=0x%04x | switch=%s",
                     packet.src, packet.dst, packet.type, dpid_to_str(event.dpid))

        # Standard MAC learning switch behavior
        self.macToPort[packet.src] = event.port

        def flood():
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        if packet.dst.is_multicast:
            flood()
        elif packet.dst not in self.macToPort:
            flood()
        else:
            out_port = self.macToPort[packet.dst]
            if out_port == event.port:
                log.warning("Same port drop for %s -> %s on %s.%s",
                            packet.src, packet.dst, dpid_to_str(event.dpid), out_port)
                return

            # Install forwarding rule with idle and hard timeouts
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data = event.ofp
            self.connection.send(msg)


class DDoSLabController(object):
    def __init__(self, model_name='ann', mitigate=False, poll_interval=5):
        core.openflow.addListeners(self)
        self.switches = {}
        self.model_name = model_name
        if isinstance(mitigate, str):
            self.mitigate = mitigate.lower() in ("true", "1", "yes")
        else:
            self.mitigate = bool(mitigate)
        self.poll_interval = int(poll_interval)
        self.blocked_ips = set()
        
        # Initialize logger
        self.eval_logger = None
        if SCORING_AVAILABLE:
            try:
                self.eval_logger = EvalLogger(log_dir="logs", run_id=f"pox_live_{self.model_name}")
            except Exception:
                pass

        # Poll flow counters periodically
        Timer(self.poll_interval, self._request_stats, recurring=True)
        log.info("DDoS Lab controller initialized [Model: %s | Mitigate: %s | Polling: %ds]",
                 self.model_name, self.mitigate, self.poll_interval)

    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.info("Switch connected: %s", dpid)
        LearningSwitch(event.connection)
        self.switches[event.dpid] = event.connection

    def _handle_ConnectionDown(self, event):
        dpid = dpid_to_str(event.dpid)
        log.info("Switch disconnected: %s", dpid)
        self.switches.pop(event.dpid, None)

    def _request_stats(self):
        for dpid, conn in list(self.switches.items()):
            sr = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            conn.send(sr)

    def _handle_FlowStatsReceived(self, event):
        stats = event.stats
        dpid = dpid_to_str(event.dpid)
        if not stats:
            log.info("[FLOW-STATS] switch=%s | active flows: 0", dpid)
            return

        log.info("[FLOW-STATS] switch=%s | active flows: %d", dpid, len(stats))
        for stat in stats:
            duration = stat.duration_sec + (stat.duration_nsec / 1e9)
            m = stat.match
            log.info("[FLOW-STATS] flow: nw_src=%s nw_dst=%s proto=%s tp_src=%s tp_dst=%s | packets=%d bytes=%d duration=%.2fs",
                     m.nw_src, m.nw_dst, m.nw_proto, m.tp_src, m.tp_dst,
                     stat.packet_count, stat.byte_count, duration)

            # Perform real-time ML inference on active IP flows
            if SCORING_AVAILABLE and duration > 0 and stat.packet_count > 5:
                self._evaluate_flow(event.connection, dpid, m, stat, duration)

    def _evaluate_flow(self, conn, dpid, m, stat, duration):
        dur_us = max(1.0, duration * 1e6)
        dur_sec = max(0.001, duration)
        flow_byts_s = stat.byte_count / dur_sec
        flow_pkts_s = stat.packet_count / dur_sec
        pkt_size_avg = stat.byte_count / max(1, stat.packet_count)

        # 12-feature vector:
        # [Dst Port, Protocol, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts,
        #  TotLen Fwd Pkts, TotLen Bwd Pkts, Flow Byts/s, Flow Pkts/s,
        #  Pkt Len Var, Down/Up Ratio, Pkt Size Avg]
        dst_port = m.tp_dst or 80
        proto = m.nw_proto or 6
        feat_vec = np.array([
            dst_port, proto, dur_us,
            stat.packet_count, 0.0,
            stat.byte_count, 0.0,
            flow_byts_s, flow_pkts_s,
            0.0, 0.0, pkt_size_avg
        ], dtype=np.float32)

        try:
            t0 = time.perf_counter()
            probs = scoring.predict_ddos_prob(feat_vec, model_name=self.model_name)[0]
            lat_us = (time.perf_counter() - t0) * 1e6

            prob_benign = float(probs[0])
            prob_ddos = float(probs[1])
            is_attack = (prob_ddos >= 0.5)
            pred_label = "DDoS" if is_attack else "Benign"

            flow_id = f"{m.nw_src}->{m.nw_dst}:{dst_port}"

            if is_attack:
                log.warning("[ALERT] DDoS detected on flow=%s (switch=%s) | P(DDoS)=%.4f | latency=%.1f us",
                            flow_id, dpid, prob_ddos, lat_us)

                if self.mitigate and m.nw_src and str(m.nw_src) not in self.blocked_ips:
                    self._apply_mitigation(conn, dpid, m.nw_src)
            else:
                log.info("[CLASSIFIER] flow=%s | P(Benign)=%.4f P(DDoS)=%.4f [Clean]",
                         flow_id, prob_benign, prob_ddos)

            if self.eval_logger:
                self.eval_logger.log_record(
                    test_suite="mininet_live",
                    model_name=self.model_name,
                    flow_id=flow_id,
                    duration_sec=duration,
                    packet_rate=flow_pkts_s,
                    byte_rate=flow_byts_s,
                    prob_benign=prob_benign,
                    prob_ddos=prob_ddos,
                    predicted_label=pred_label,
                    latency_us=lat_us
                )
        except Exception as e:
            log.error("Inference evaluation failed: %s", e)

    def _apply_mitigation(self, conn, dpid, src_ip):
        """Installs high-priority OpenFlow DROP rule to isolate attacker."""
        log.warning("[MITIGATION] Blocking attacking source IP %s on switch %s", src_ip, dpid)
        self.blocked_ips.add(str(src_ip))

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = src_ip
        msg.priority = 65535       # Highest priority rule
        msg.idle_timeout = 60      # Block for 60 seconds
        # No output actions appended = DROP packets at line rate in switch kernel
        conn.send(msg)
        log.info("[MITIGATION] Drop flow rule installed for %s (priority 65535, timeout 60s)", src_ip)


def launch(model='ann', mitigate=False, poll_interval=5):
    core.registerNew(DDoSLabController, model_name=model, mitigate=mitigate, poll_interval=poll_interval)
