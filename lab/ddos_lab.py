"""
POX controller component for the SDN DDoS lab.
Implements an L2 learning switch with packet-in logging and periodic flow-stats polling.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import pox.lib.packet as pkt
import time

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
    def __init__(self):
        core.openflow.addListeners(self)
        self.switches = {}
        # Poll flow counters every 5 seconds
        Timer(5, self._request_stats, recurring=True)
        log.info("DDoS Lab controller initialized (polling flow stats every 5s)")

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


def launch():
    core.registerNew(DDoSLabController)
