#!/usr/bin/env python3
"""
run_benchmark.py - Offline PCAP evaluation and CPU latency benchmark across
the three 12-feature models (ann, paper_cnn, custom_cnn).
"""

import os
import time
import subprocess
import numpy as np
from datetime import datetime

import scoring
from eval_logger import EvalLogger

def extract_flows_from_pcap(pcap_path, window_sec=1.0, default_label="Benign", is_attack_pcap=False):
    """
    Extracts 12-feature flow vectors from a pcap file using tshark field extraction.
    Windows traffic into 1-second flow slices matching OpenFlow 1.0 telemetry.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Extract frame timestamp, protocol, ports, IPs, and frame length via tshark
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len"
    ]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Store packets
    packets = []
    for line in proc.stdout:
        parts = line.strip().split("\t")
        if len(parts) < 7:
            continue
        try:
            epoch = float(parts[0])
            proto = int(parts[1]) if parts[1] else 6  # default TCP
            dst_port = int(parts[2]) if parts[2] else (int(parts[3]) if parts[3] else 80)
            src_ip = parts[4]
            dst_ip = parts[5]
            length = float(parts[6]) if parts[6] else 64.0
            packets.append((epoch, proto, dst_port, src_ip, dst_ip, length))
        except (ValueError, IndexError):
            continue

    proc.wait()
    if not packets:
        print(f"[warning] No packets extracted from {pcap_path}")
        return []

    # Sort packets by timestamp
    packets.sort(key=lambda p: p[0])
    t_start = packets[0][0]
    t_end = packets[-1][0]

    flows = []
    # Window traffic into slices of `window_sec` seconds
    curr_t = t_start
    while curr_t < t_end:
        w_end = curr_t + window_sec
        # Filter packets in current window
        w_pkts = [p for p in packets if curr_t <= p[0] < w_end]
        curr_t = w_end

        if not w_pkts:
            continue

        # Determine ground truth label
        # In attack_30s.pcap: 0-5s is benign baseline, 5-25s is active SYN flood, 25-30s is recovery
        elapsed = w_pkts[0][0] - t_start
        if is_attack_pcap:
            label = "DDoS" if (5.0 <= elapsed <= 25.0) else "Benign"
        else:
            label = default_label

        # Compute flow statistics
        dur_sec = max(0.001, w_pkts[-1][0] - w_pkts[0][0])
        dur_us = dur_sec * 1e6
        total_pkts = len(w_pkts)
        lengths = [p[5] for p in w_pkts]
        total_bytes = sum(lengths)

        # Distinguish forward vs backward packets (victim is 10.0.0.2)
        fwd_pkts = [p for p in w_pkts if p[4] == "10.0.0.2"]
        bwd_pkts = [p for p in w_pkts if p[3] == "10.0.0.2"]

        tot_fwd_pkts = len(fwd_pkts) if fwd_pkts else total_pkts
        tot_bwd_pkts = len(bwd_pkts)
        tot_len_fwd = sum(p[5] for p in fwd_pkts) if fwd_pkts else total_bytes
        tot_len_bwd = sum(p[5] for p in bwd_pkts)

        flow_byts_s = total_bytes / dur_sec
        flow_pkts_s = total_pkts / dur_sec
        pkt_len_var = float(np.var(lengths)) if len(lengths) > 1 else 0.0
        down_up_ratio = float(tot_bwd_pkts) / (float(tot_fwd_pkts) + 1e-5)
        pkt_size_avg = total_bytes / total_pkts

        # Form the exact 12-feature vector:
        # 0: Dst Port, 1: Protocol, 2: Flow Duration, 3: Tot Fwd Pkts, 4: Tot Bwd Pkts,
        # 5: TotLen Fwd Pkts, 6: TotLen Bwd Pkts, 7: Flow Byts/s, 8: Flow Pkts/s,
        # 9: Pkt Len Var, 10: Down/Up Ratio, 11: Pkt Size Avg
        proto_sample = w_pkts[0][1]
        dst_port_sample = w_pkts[0][2]

        feat_vector = np.array([
            dst_port_sample,
            proto_sample,
            dur_us,
            tot_fwd_pkts,
            tot_bwd_pkts,
            tot_len_fwd,
            tot_len_bwd,
            flow_byts_s,
            flow_pkts_s,
            pkt_len_var,
            down_up_ratio,
            pkt_size_avg
        ], dtype=np.float32)

        flow_id = f"win_{elapsed:.1f}s_proto{proto_sample}_p{dst_port_sample}"
        flows.append({
            "flow_id": flow_id,
            "vector": feat_vector,
            "duration_sec": dur_sec,
            "packet_rate": flow_pkts_s,
            "byte_rate": flow_byts_s,
            "ground_truth": label
        })

    return flows

def run_offline_pcap_benchmark(logger, captures_dir=None):
    """Runs all 3 models on the benign and attack PCAP captures."""
    cand_dirs = [
        captures_dir,
        "captures",
        "../captures",
        "lab/captures",
        "/home/mininet/project/captures"
    ]
    cap_dir = next((d for d in cand_dirs if d and os.path.exists(d)), None)
    if not cap_dir:
        print("[skip] No captures directory found. Skipping offline PCAP benchmark.")
        return

    benign_pcap = os.path.join(cap_dir, "benign_60s.pcap")
    attack_pcap = os.path.join(cap_dir, "attack_30s.pcap")

    if not os.path.exists(benign_pcap) or not os.path.exists(attack_pcap):
        print(f"[skip] Missing pcap files in {cap_dir}. Skipping.")
        return

    print("\n--- Offline PCAP Flow Benchmark ---")
    print(f"Reading benign capture: {benign_pcap}")
    benign_flows = extract_flows_from_pcap(benign_pcap, window_sec=1.0, default_label="Benign", is_attack_pcap=False)
    print(f"  -> Extracted {len(benign_flows)} benign 1-second flow windows.")

    print(f"Reading attack capture: {attack_pcap}")
    attack_flows = extract_flows_from_pcap(attack_pcap, window_sec=1.0, is_attack_pcap=True)
    print(f"  -> Extracted {len(attack_flows)} attack/baseline 1-second flow windows.")

    all_flows = benign_flows + attack_flows
    print(f"Total evaluation samples: {len(all_flows)}")

    models = ["ann", "paper_cnn", "custom_cnn"]
    scoring.load_scaler()

    for m in models:
        print(f"\nEvaluating {m}...")
        # Pre-load weights so disk I/O isn't counted in inference latency
        scoring.load_weights(m)
        for flow in all_flows:
            x = flow["vector"]
            t0 = time.perf_counter()
            probs = scoring.predict_ddos_prob(x, model_name=m)[0]
            lat_us = (time.perf_counter() - t0) * 1e6

            prob_benign = float(probs[0])
            prob_ddos = float(probs[1])
            pred_label = "DDoS" if prob_ddos >= 0.5 else "Benign"

            logger.log_record(
                test_suite="offline_pcap",
                model_name=m,
                flow_id=flow["flow_id"],
                duration_sec=flow["duration_sec"],
                packet_rate=flow["packet_rate"],
                byte_rate=flow["byte_rate"],
                prob_benign=prob_benign,
                prob_ddos=prob_ddos,
                predicted_label=pred_label,
                ground_truth=flow["ground_truth"],
                latency_us=lat_us
            )

    print("\nOffline PCAP flow benchmark complete.")

def run_latency_benchmark():
    """Profiles per-sample CPU inference latency across all three models."""
    print("\n--- CPU Inference Latency & Throughput Benchmark ---")
    dummy_x = np.random.rand(1, 12).astype(np.float32)
    stats = scoring.benchmark_inference(dummy_x, num_runs=200)

    print(f"{'Model Architecture':<20} | {'Mean Latency':<15} | {'Median (p50)':<15} | {'p99 Latency':<15} | {'Max Throughput':<18}")
    print("-" * 90)
    for m, stat in stats.items():
        throughput = 1e6 / stat['mean_us'] if stat['mean_us'] > 0 else 0
        print(f"{m:<20} | {stat['mean_us']:>8.1f} us     | {stat['p50_us']:>8.1f} us     | {stat['p99_us']:>8.1f} us     | {throughput:>10.0f} flows/s")

def main():
    print("Starting DDoS Model Benchmark...")
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    logger = EvalLogger(log_dir="logs", run_id=run_id)

    run_offline_pcap_benchmark(logger)
    run_latency_benchmark()

    summary, md_report = logger.generate_summary()
    print("\n--- Evaluation Summary ---")
    print(md_report)

    print(f"\nDetailed CSV records saved to: {logger.csv_path}")
    print(f"Summary Markdown saved to:     {os.path.join(logger.log_dir, f'benchmark_summary_{run_id}.md')}")
    print(f"Summary JSON saved to:         {os.path.join(logger.log_dir, f'benchmark_summary_{run_id}.json')}")

if __name__ == "__main__":
    main()
