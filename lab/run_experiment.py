"""
Experiment runner comparing benign baseline traffic against a spoofed SYN flood.
Measures controller packet-in rates, ping RTTs, and HTTP availability across
baseline, attack, and recovery periods.
"""

import time
import re
import os
import subprocess
from topo import create_network
from mininet.log import setLogLevel, info

def get_pox_packet_in_count(log_path=None):
    candidates = [
        log_path,
        'pox_ddos_lab.log',
        '../pox_ddos_lab.log',
        '/home/mininet/project/pox_ddos_lab.log',
        '/tmp/pox_ddos_lab.log'
    ]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                with open(p, 'r') as f:
                    content = f.read()
                return len(re.findall(r'\[PACKET-IN\]', content))
            except Exception:
                pass
    return 0

def parse_ping_rtt(ping_output):
    match = re.search(r'rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)', ping_output)
    loss_match = re.search(r'(\d+)% packet loss', ping_output)
    loss = float(loss_match.group(1)) if loss_match else 0.0
    if match:
        return {
            'avg': float(match.group(2)),
            'loss': loss,
            'summary': f"avg={match.group(2)}ms (loss={loss}%)"
        }
    return {'avg': None, 'loss': loss, 'summary': f"100% loss"}

def run():
    setLogLevel('info')
    info('*** Creating Mininet network\n')
    net = create_network()
    net.start()
    
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
    
    info('*** Setting up Python HTTP server and iperf3 server daemon on h2\n')
    h2.cmd('python3 -m http.server 80 > /tmp/http_server.log 2>&1 &')
    h2.cmd('iperf3 -s -D')
    time.sleep(2)
    
    # Warm-up ping to discover ARP/MACs
    h1.cmd('ping -c 1 10.0.0.2')
    h3.cmd('ping -c 1 10.0.0.2')
    h4.cmd('ping -c 1 10.0.0.2')
    time.sleep(1)
    
    # Baseline phase
    info('\n=== [Baseline: Benign Traffic] ===\n')
    pkts_start_base = get_pox_packet_in_count()
    t_start_base = time.time()
    
    info('Running benign iperf3 flow (h3 -> h2) and HTTP requests...\n')
    iperf_out = h3.cmd('iperf3 -c 10.0.0.2 -t 3')
    print("Benign iperf3 output:\n" + "\n".join(iperf_out.strip().splitlines()[-4:]))
    
    h3_http = h3.cmd('wget -q -O /dev/null -T 2 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')
    h4_http = h4.cmd('wget -q -O /dev/null -T 2 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')
    print(f"Benign HTTP requests: h3: {h3_http.strip()}, h4: {h4_http.strip()}")
    
    base_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    base_stats = parse_ping_rtt(base_ping)
    t_elapsed_base = time.time() - t_start_base
    pkts_base = get_pox_packet_in_count() - pkts_start_base
    rate_base = pkts_base / t_elapsed_base if t_elapsed_base > 0 else 0
    print(f"--> Baseline Latency: {base_stats['summary']} | Packet-in rate: {rate_base:.1f} pkts/s")
    
    # Attack phase
    info('\n=== [Attack: Spoofed SYN Flood] ===\n')
    info('Launching: timeout 15 hping3 --flood -S -p 80 --rand-source 10.0.0.2\n')
    pkts_start_atk = get_pox_packet_in_count()
    t_start_atk = time.time()
    
    # Launch attack from h1
    h1.cmd('timeout 15 hping3 --flood -S -p 80 --rand-source 10.0.0.2 > /dev/null 2>&1 &')
    time.sleep(3)  # Let flood hit the switch
    
    atk_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    atk_stats = parse_ping_rtt(atk_ping)
    
    atk_http = h3.cmd('wget -q -O /dev/null -T 2 http://10.0.0.2:80/ && echo "HTTP OK" || echo "HTTP TIMEOUT/FAILED"')
    print(f"Under-attack HTTP request from benign h3: {atk_http.strip()}")
    
    time.sleep(7)
    t_elapsed_atk = time.time() - t_start_atk
    pkts_atk = get_pox_packet_in_count() - pkts_start_atk
    rate_atk = pkts_atk / t_elapsed_atk if t_elapsed_atk > 0 else 0
    print(f"--> Under-Attack Latency: {atk_stats['summary']} | Packet-in rate: {rate_atk:.1f} pkts/s")
    
    # Ensure hping3 has terminated
    info('Stopping attack and waiting for traffic to clear...\n')
    os.system('sudo pkill -9 -f hping3 >/dev/null 2>&1 || true')
    time.sleep(5)
    
    # Recovery phase
    info('\n=== [Recovery: Post-Attack Baseline] ===\n')
    pkts_start_rec = get_pox_packet_in_count()
    t_start_rec = time.time()
    
    rec_http = h3.cmd('wget -q -O /dev/null -T 2 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')
    print(f"Recovery HTTP request from benign h3: {rec_http.strip()}")
    
    rec_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    rec_stats = parse_ping_rtt(rec_ping)
    t_elapsed_rec = time.time() - t_start_rec
    pkts_rec = get_pox_packet_in_count() - pkts_start_rec
    rate_rec = pkts_rec / t_elapsed_rec if t_elapsed_rec > 0 else 0
    print(f"--> Recovery Latency: {rec_stats['summary']} | Packet-in rate: {rate_rec:.1f} pkts/s")
    
    # Summary Table
    print("\n" + "-"*70)
    print("Traffic and Latency Measurement Summary")
    print("-" * 70)
    print(f"{'Condition':<15} | {'Packet-In Rate':<20} | {'h3 -> h2 Latency':<18} | {'HTTP Status':<12}")
    print("-" * 70)
    print(f"{'Baseline':<15} | {f'{rate_base:.1f} pkts/s':<20} | {base_stats['summary']:<18} | {h3_http.strip():<12}")
    print(f"{'Under Attack':<15} | {f'{rate_atk:.1f} pkts/s':<20} | {atk_stats['summary']:<18} | {atk_http.strip():<12}")
    print(f"{'Recovery':<15} | {f'{rate_rec:.1f} pkts/s':<20} | {rec_stats['summary']:<18} | {rec_http.strip():<12}")
    print("-" * 70)
    
    # Cleanup
    h2.cmd('pkill -9 -f "http.server" || true')
    h2.cmd('pkill -9 -f iperf3 || true')
    net.stop()

if __name__ == '__main__':
    run()
