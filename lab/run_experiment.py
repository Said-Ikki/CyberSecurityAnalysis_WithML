"""
Experiment runner comparing benign baseline traffic against a spoofed SYN flood.
Measures controller packet-in rates, ping RTTs, and HTTP availability across
baseline, attack, and recovery periods. Logs structured metrics to CSV.
"""

import time
import re
import os
import csv
import argparse
from datetime import datetime
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
    return {'avg': None, 'loss': loss, 'summary': "100% loss"}

def run_experiment(model_name="ann", mitigate=False, log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(log_dir, f"experiment_{model_name}_{run_id}.csv")

    setLogLevel('info')
    info(f'\n*** Starting Mininet DDoS Experiment [Model: {model_name} | Mitigate: {mitigate}] ***\n')
    net = create_network()
    net.start()

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    info('*** Setting up HTTP server and iperf3 server daemon on h2\n')
    h2.cmd('python3 -m http.server 80 > /tmp/http_server.log 2>&1 &')
    h2.cmd('iperf3 -s -D')
    time.sleep(2)

    # Warm-up ping to discover ARP/MACs
    h1.cmd('ping -c 1 10.0.0.2')
    h3.cmd('ping -c 1 10.0.0.2')
    h4.cmd('ping -c 1 10.0.0.2')
    time.sleep(1)

    # 1. Baseline phase
    info('\n=== [1. Baseline: Benign Traffic] ===\n')
    pkts_start_base = get_pox_packet_in_count()
    t_start_base = time.time()

    info('Running benign iperf3 flow (h3 -> h2) and HTTP requests...\n')
    iperf_out = h3.cmd('iperf3 -c 10.0.0.2 -t 3')
    print("Benign iperf3 output:\n" + "\n".join(iperf_out.strip().splitlines()[-4:]))

    h3_http_base = h3.cmd('wget -q -O /dev/null -T 2 -t 1 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')
    h4_http_base = h4.cmd('wget -q -O /dev/null -T 2 -t 1 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')

    base_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    base_stats = parse_ping_rtt(base_ping)
    t_elapsed_base = time.time() - t_start_base
    pkts_base = get_pox_packet_in_count() - pkts_start_base
    rate_base = pkts_base / t_elapsed_base if t_elapsed_base > 0 else 0
    print(f"--> Baseline Latency: {base_stats['summary']} | Packet-in rate: {rate_base:.1f} pkts/s")

    # 2. Attack phase
    info('\n=== [2. Attack: Spoofed SYN Flood] ===\n')
    info('Launching: timeout 15 hping3 --flood -S -p 80 --rand-source 10.0.0.2\n')
    pkts_start_atk = get_pox_packet_in_count()
    t_start_atk = time.time()

    h1.cmd('timeout 15 hping3 --flood -S -p 80 --rand-source 10.0.0.2 > /dev/null 2>&1 &')
    time.sleep(3)  # Let flood hit the switch

    atk_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    atk_stats = parse_ping_rtt(atk_ping)

    atk_http = h3.cmd('wget -q -O /dev/null -T 2 -t 1 http://10.0.0.2:80/ && echo "HTTP OK" || echo "HTTP TIMEOUT/FAILED"')
    print(f"Under-attack HTTP request from benign h3: {atk_http.strip()}")

    time.sleep(7)
    t_elapsed_atk = time.time() - t_start_atk
    pkts_atk = get_pox_packet_in_count() - pkts_start_atk
    rate_atk = pkts_atk / t_elapsed_atk if t_elapsed_atk > 0 else 0
    print(f"--> Under-Attack Latency: {atk_stats['summary']} | Packet-in rate: {rate_atk:.1f} pkts/s")

    # Stop attack
    info('Stopping attack and waiting for traffic to clear...\n')
    os.system('sudo pkill -9 -f hping3 >/dev/null 2>&1 || true')
    time.sleep(5)

    # 3. Recovery phase
    info('\n=== [3. Recovery: Post-Attack Baseline] ===\n')
    pkts_start_rec = get_pox_packet_in_count()
    t_start_rec = time.time()

    rec_http = h3.cmd('wget -q -O /dev/null -T 2 -t 1 http://10.0.0.2:80/ && echo "HTTP 200 OK" || echo "HTTP Failed"')
    rec_ping = h3.cmd('ping -c 5 -i 0.2 -W 1 10.0.0.2')
    rec_stats = parse_ping_rtt(rec_ping)
    t_elapsed_rec = time.time() - t_start_rec
    pkts_rec = get_pox_packet_in_count() - pkts_start_rec
    rate_rec = pkts_rec / t_elapsed_rec if t_elapsed_rec > 0 else 0
    print(f"--> Recovery Latency: {rec_stats['summary']} | Packet-in rate: {rate_rec:.1f} pkts/s")

    # Summary Table
    print("\n" + "-" * 75)
    print(f"Experiment Summary [Model: {model_name} | Mitigate: {mitigate}]")
    print("-" * 75)
    print(f"{'Condition':<15} | {'Packet-In Rate':<20} | {'h3 -> h2 Latency':<18} | {'HTTP Status':<12}")
    print("-" * 75)
    print(f"{'Baseline':<15} | {f'{rate_base:.1f} pkts/s':<20} | {base_stats['summary']:<18} | {h3_http_base.strip():<12}")
    print(f"{'Under Attack':<15} | {f'{rate_atk:.1f} pkts/s':<20} | {atk_stats['summary']:<18} | {atk_http.strip():<12}")
    print(f"{'Recovery':<15} | {f'{rate_rec:.1f} pkts/s':<20} | {rec_stats['summary']:<18} | {rec_http.strip():<12}")
    print("-" * 75)

    # Save to CSV
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["condition", "model_name", "mitigate", "packet_in_rate", "avg_rtt_ms", "packet_loss_pct", "http_status"])
        writer.writerow(["Baseline", model_name, mitigate, f"{rate_base:.2f}", base_stats['avg'], base_stats['loss'], h3_http_base.strip()])
        writer.writerow(["Under Attack", model_name, mitigate, f"{rate_atk:.2f}", atk_stats['avg'], atk_stats['loss'], atk_http.strip()])
        writer.writerow(["Recovery", model_name, mitigate, f"{rate_rec:.2f}", rec_stats['avg'], rec_stats['loss'], rec_http.strip()])
    print(f"Experiment log saved to: {csv_path}")

    # Cleanup
    h2.cmd('pkill -9 -f "http.server" || true')
    h2.cmd('pkill -9 -f iperf3 || true')
    net.stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SDN DDoS Experiment Runner")
    parser.add_argument("--model", default="ann", choices=["ann", "paper_cnn", "custom_cnn"], help="Model to evaluate")
    parser.add_argument("--mitigate", action="store_true", help="Enable automated flow drop mitigation")
    args = parser.parse_args()

    run_experiment(model_name=args.model, mitigate=args.mitigate)
