#!/usr/bin/env python3
"""
run_all_models.py - Runs the Mininet flood experiment across all three models
(ann, paper_cnn, custom_cnn) and aggregates the results across one or more runs.
"""

import os
import time
import glob
import json
import csv
import argparse
import subprocess
from datetime import datetime
import numpy as np

MODELS = ["ann", "paper_cnn", "custom_cnn"]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = SCRIPT_DIR if os.path.exists(os.path.join(SCRIPT_DIR, "run_experiment.py")) else "/home/mininet/project"
VENV_PY = os.path.join(PROJECT_DIR, "venv", "bin", "python3")
if not os.path.exists(VENV_PY):
    VENV_PY = "/home/mininet/project/venv/bin/python3"
POX_BIN = "/home/mininet/pox/pox.py"


def cleanup():
    os.system("sudo pkill -9 -f pox >/dev/null 2>&1 || true")
    os.system("sudo pkill -9 -f hping3 >/dev/null 2>&1 || true")
    os.system("sudo pkill -9 -f 'http.server' >/dev/null 2>&1 || true")
    os.system("sudo pkill -9 -f iperf3 >/dev/null 2>&1 || true")
    os.system("sudo mn -c >/dev/null 2>&1")
    time.sleep(2)


def start_pox(model_name, mitigate=True):
    log_file = os.path.join(PROJECT_DIR, "pox_ddos_lab.log")
    with open(log_file, "w") as f:
        f.write("")

    mitigate_arg = "True" if mitigate else "False"
    cmd = f"{VENV_PY} {POX_BIN} ddos_lab --model={model_name} --mitigate={mitigate_arg} > {log_file} 2>&1 &"
    os.system(cmd)
    time.sleep(3)


def run_single_experiment(model_name, run_idx=1, mitigate=True):
    print(f"\n--- Running [{model_name}] (Run {run_idx}, mitigate={mitigate}) ---")
    cleanup()
    start_pox(model_name, mitigate)

    exp_script = os.path.join(PROJECT_DIR, "run_experiment.py")
    cmd = ["sudo", "python3", exp_script, "--model", model_name]
    if mitigate:
        cmd.append("--mitigate")

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(proc.stdout)

    pox_log = ""
    pox_log_path = os.path.join(PROJECT_DIR, "pox_ddos_lab.log")
    if os.path.exists(pox_log_path):
        with open(pox_log_path, "r") as f:
            pox_log = f.read()

    alerts = [line for line in pox_log.splitlines() if "[ALERT]" in line]
    mitigations = [line for line in pox_log.splitlines() if "Drop flow rule installed" in line]
    print(f"[{model_name} run {run_idx}] Alerts: {len(alerts)} | Drop rules installed: {len(mitigations)}")

    cleanup()

    logs_dir = os.path.join(PROJECT_DIR, "logs")
    csv_candidates = sorted(glob.glob(os.path.join(logs_dir, f"experiment_{model_name}_*.csv")))
    metrics = {
        "model_name": model_name,
        "run_idx": run_idx,
        "alerts_count": len(alerts),
        "mitigation_rules": len(mitigations),
    }

    if csv_candidates:
        latest_csv = csv_candidates[-1]
        with open(latest_csv, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cond = row["condition"].lower().replace(" ", "_")
                metrics[f"{cond}_pkt_in_rate"] = float(row["packet_in_rate"]) if row["packet_in_rate"] else 0.0
                metrics[f"{cond}_rtt_ms"] = float(row["avg_rtt_ms"]) if row["avg_rtt_ms"] not in ("", "None", None) else None
                metrics[f"{cond}_loss_pct"] = float(row["packet_loss_pct"]) if row["packet_loss_pct"] else 0.0
                metrics[f"{cond}_http"] = row["http_status"]

    return metrics


def _safe_mean(vals):
    valid = [v for v in vals if v is not None]
    return float(np.mean(valid)) if valid else None


def main():
    parser = argparse.ArgumentParser(description="Run multi-model SDN DDoS experiments")
    parser.add_argument("--runs", type=int, default=1, help="Number of runs per model")
    parser.add_argument("--no-mitigate", action="store_true", help="Disable automated drop rules")
    args = parser.parse_args()

    mitigate = not args.no_mitigate
    logs_dir = os.path.join(PROJECT_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    print(f"Starting multi-model evaluation ({args.runs} run(s) per model, mitigate={mitigate})...")
    all_runs = []

    for m in MODELS:
        for r_idx in range(1, args.runs + 1):
            res = run_single_experiment(m, run_idx=r_idx, mitigate=mitigate)
            all_runs.append(res)
            time.sleep(2)

    # Save raw run data
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = os.path.join(logs_dir, f"all_runs_{ts}.json")
    with open(raw_path, "w") as f:
        json.dump(all_runs, f, indent=2)

    # Aggregate averages per model
    print("\n--- Averaged Results Across Models ---")
    print(f"{'Model':<12} | {'Base RTT':<10} | {'Atk RTT':<10} | {'Atk Loss':<9} | {'Atk Pkt-In/s':<13} | {'Alerts':<7} | {'Drops':<7}")
    print("-" * 82)

    for m in MODELS:
        m_runs = [r for r in all_runs if r["model_name"] == m]
        base_rtt = _safe_mean([r.get("baseline_rtt_ms") for r in m_runs])
        atk_rtt = _safe_mean([r.get("under_attack_rtt_ms") for r in m_runs])
        atk_loss = _safe_mean([r.get("under_attack_loss_pct") for r in m_runs])
        atk_rate = _safe_mean([r.get("under_attack_pkt_in_rate") for r in m_runs])
        alerts = _safe_mean([r.get("alerts_count") for r in m_runs])
        drops = _safe_mean([r.get("mitigation_rules") for r in m_runs])

        b_str = f"{base_rtt:.3f} ms" if base_rtt is not None else "N/A"
        a_str = f"{atk_rtt:.3f} ms" if atk_rtt is not None else "N/A"
        print(f"{m:<12} | {b_str:<10} | {a_str:<10} | {atk_loss:>6.1f}%  | {atk_rate:>10.1f}/s | {alerts:>6.1f} | {drops:>6.1f}")

    print(f"\nRaw run data saved to: {raw_path}")


if __name__ == "__main__":
    main()
