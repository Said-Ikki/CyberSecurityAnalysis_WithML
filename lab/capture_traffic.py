"""
Automated traffic capture script for generating benign and attack pcaps on s1-eth2.
Captures:
  - 60s benign traffic (HTTP, iperf3 bursts, pings) -> captures/benign_60s.pcap
  - 30s attack traffic (5s baseline, 20s SYN flood, 5s recovery) -> captures/attack_30s.pcap
"""

import time
import os
import sys
import subprocess
from topo import create_network
from mininet.log import setLogLevel, info

def run():
    setLogLevel('info')
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.isdir('/home/mininet/project/captures'):
        captures_dir = '/home/mininet/project/captures'
    else:
        captures_dir = os.path.join(script_dir, 'captures')
    os.makedirs(captures_dir, exist_ok=True)
    
    benign_pcap = os.path.join(captures_dir, 'benign_60s.pcap')
    attack_pcap = os.path.join(captures_dir, 'attack_30s.pcap')
    
    info('*** Creating Mininet network for captures\n')
    net = create_network()
    net.start()
    
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    
    info('*** Starting HTTP server and iperf3 server on h2\n')
    h2.cmd('python3 -m http.server 80 > /tmp/http_server.log 2>&1 &')
    h2.cmd('iperf3 -s -D')
    time.sleep(2)
    
    # Warm-up ping
    h3.cmd('ping -c 2 10.0.0.2')
    h4.cmd('ping -c 2 10.0.0.2')
    
    # =============================================================
    # 1. 60-Second Benign-Only Capture
    # =============================================================
    os.system(f'rm -f {benign_pcap}')
    
    info('\n=== [Starting 60-second Benign-Only Capture] ===\n')
    tcpdump_cmd = f'tcpdump -i s1-eth2 -w {benign_pcap} -U > /dev/null 2>&1 &'
    os.system(f'sudo {tcpdump_cmd}')
    time.sleep(1)
    
    t_start = time.time()
    t_end = t_start + 60
    
    cycle = 0
    while time.time() < t_end:
        # Periodic HTTP requests from h3 and h4
        h3.cmd('wget -q -O /dev/null -T 1 http://10.0.0.2:80/ || true &')
        h4.cmd('wget -q -O /dev/null -T 1 http://10.0.0.2:80/ || true &')
        
        # Periodic pings
        if cycle % 5 == 0:
            h3.cmd('ping -c 2 -i 0.2 10.0.0.2 > /dev/null 2>&1 &')
            
        # iperf3 transmission at specific intervals (t=15s and t=40s)
        elapsed = time.time() - t_start
        if (14 <= elapsed <= 17) or (38 <= elapsed <= 41):
            h3.cmd('iperf3 -c 10.0.0.2 -t 3 -b 50M > /dev/null 2>&1 &')
            time.sleep(3)
            
        cycle += 1
        time.sleep(1)
        
    os.system('sudo pkill -2 -f tcpdump || true')
    time.sleep(2)
    info(f'Benign capture complete: {benign_pcap}\n')
    
    # =============================================================
    # 2. 30-Second Attack Capture
    # =============================================================
    os.system(f'rm -f {attack_pcap}')
    
    info('\n=== [Starting 30-second Attack Capture] ===\n')
    os.system(f'sudo tcpdump -i s1-eth2 -w {attack_pcap} -U > /dev/null 2>&1 &')
    time.sleep(1)
    
    t_start = time.time()
    # 0s - 5s: Baseline benign before attack
    info('t=0s to 5s: Pre-attack benign baseline\n')
    for _ in range(5):
        h3.cmd('wget -q -O /dev/null -T 1 http://10.0.0.2:80/ || true &')
        h3.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 &')
        time.sleep(1)
        
    # 5s - 25s: Active SYN flood attack from h1
    info('t=5s to 25s: Active SYN flood attack from h1 (timeout 20 hping3 --flood)\n')
    h1.cmd('timeout 20 hping3 --flood -S -p 80 --rand-source 10.0.0.2 > /dev/null 2>&1 &')
    
    for _ in range(20):
        h3.cmd('wget -q -O /dev/null -T 1 http://10.0.0.2:80/ || true &')
        time.sleep(1)
        
    os.system('sudo pkill -9 -f hping3 >/dev/null 2>&1 || true')
    info('t=25s to 30s: Attack stopped, post-attack recovery\n')
    for _ in range(5):
        h3.cmd('wget -q -O /dev/null -T 1 http://10.0.0.2:80/ || true &')
        h3.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 &')
        time.sleep(1)
        
    os.system('sudo pkill -2 -f tcpdump || true')
    time.sleep(2)
    info(f'Attack capture complete: {attack_pcap}\n')
    
    # Cleanup
    h2.cmd('pkill -9 -f "http.server" || true')
    h2.cmd('pkill -9 -f iperf3 || true')
    net.stop()
    info('*** Mininet network stopped\n')

if __name__ == '__main__':
    run()
