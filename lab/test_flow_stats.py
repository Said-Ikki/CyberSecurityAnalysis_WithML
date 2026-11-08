"""
Basic smoke test for POX flow stats and packet-in logging.
Starts a 4-host Mininet topology, runs ping and iperf3 between h1 and h2,
and waits for the 5-second controller stats polling timer to fire.
"""

import time
import sys
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel, info

def run():
    setLogLevel('info')
    topo = SingleSwitchTopo(k=4)
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), switch=OVSSwitch)
    
    info('*** Starting Mininet network\n')
    net.start()
    
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    
    info('*** Waiting for switch connection\n')
    time.sleep(2)
    
    info('*** Running h1 ping -c 3 h2\n')
    ping_out = h1.cmd('ping -c 3 10.0.0.2')
    print(ping_out)
    
    info('*** Starting iperf3 server daemon on h2\n')
    h2.cmd('iperf3 -s -D')
    time.sleep(1)
    
    info('*** Running iperf3 client from h1 to h2 (3s)\n')
    iperf_out = h1.cmd('iperf3 -c 10.0.0.2 -t 3')
    print(iperf_out)
    
    info('*** Waiting 7s for periodic flow stats timer to trigger and collect counters\n')
    time.sleep(7)
    
    info('*** Stopping iperf3 server\n')
    h2.cmd('pkill -9 iperf3')
    
    info('*** Stopping Mininet\n')
    net.stop()

if __name__ == '__main__':
    run()
