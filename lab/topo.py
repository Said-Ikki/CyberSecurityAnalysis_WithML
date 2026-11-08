"""
Mininet single-switch topology for the DDoS lab.
Hosts:
  h1: Attacker (10.0.0.1)
  h2: Victim Server (10.0.0.2)
  h3, h4: Benign clients (10.0.0.3, 10.0.0.4)
Switch s1 connects to a remote OpenFlow controller at 127.0.0.1:6633.
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class DDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

def create_network(controller_ip='127.0.0.1', controller_port=6633):
    topo = DDoSTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip=controller_ip, port=controller_port),
        autoSetMacs=True,
        autoStaticArp=False
    )
    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = create_network()
    net.start()
    info('*** Network started. Hosts: h1 (attacker), h2 (victim), h3/h4 (benign)\n')
    CLI(net)
    net.stop()
