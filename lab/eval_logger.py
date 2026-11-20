"""
eval_logger.py - Logs per-flow predictions and inference latency to CSV,
and computes summary metrics (accuracy, precision, recall, F1, FPR) across models.
"""

import os
import csv
import json
from datetime import datetime
import numpy as np

class EvalLogger:
    def __init__(self, log_dir="logs", run_id=None):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(self.log_dir, f"eval_records_{self.run_id}.csv")
        self.records = []
        self._init_csv()

    def _init_csv(self):
        headers = [
            "timestamp", "test_suite", "model_name", "flow_id",
            "duration_sec", "packet_rate", "byte_rate",
            "prob_benign", "prob_ddos", "predicted_label",
            "ground_truth", "is_correct", "latency_us"
        ]
        with open(self.csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    def log_record(self, test_suite, model_name, flow_id, duration_sec,
                   packet_rate, byte_rate, prob_benign, prob_ddos,
                   predicted_label, ground_truth=None, latency_us=0.0):
        """Logs a single flow evaluation record to the CSV and in-memory buffer."""
        ts = datetime.now().isoformat()
        is_correct = None
        if ground_truth:
            is_correct = (predicted_label.lower() == ground_truth.lower())

        row = [
            ts, test_suite, model_name, flow_id,
            f"{duration_sec:.4f}", f"{packet_rate:.2f}", f"{byte_rate:.2f}",
            f"{prob_benign:.6f}", f"{prob_ddos:.6f}", predicted_label,
            ground_truth or "Unknown",
            "" if is_correct is None else str(is_correct),
            f"{latency_us:.2f}"
        ]

        with open(self.csv_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        self.records.append({
            "timestamp": ts,
            "test_suite": test_suite,
            "model_name": model_name,
            "flow_id": flow_id,
            "duration_sec": duration_sec,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "prob_benign": prob_benign,
            "prob_ddos": prob_ddos,
            "predicted_label": predicted_label,
            "ground_truth": ground_truth,
            "is_correct": is_correct,
            "latency_us": latency_us
        })

    def compute_model_metrics(self, model_name=None, test_suite=None):
        """Computes aggregate performance metrics for a model."""
        recs = self.records
        if model_name:
            recs = [r for r in recs if r["model_name"] == model_name]
        if test_suite:
            recs = [r for r in recs if r["test_suite"] == test_suite]

        if not recs:
            return None

        tp = sum(1 for r in recs if r["predicted_label"] == "DDoS" and r["ground_truth"] == "DDoS")
        fp = sum(1 for r in recs if r["predicted_label"] == "DDoS" and r["ground_truth"] == "Benign")
        tn = sum(1 for r in recs if r["predicted_label"] == "Benign" and r["ground_truth"] == "Benign")
        fn = sum(1 for r in recs if r["predicted_label"] == "Benign" and r["ground_truth"] == "DDoS")

        total = len(recs)
        labeled = tp + fp + tn + fn

        accuracy = (tp + tn) / labeled if labeled > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        latencies = [r["latency_us"] for r in recs if r["latency_us"] > 0]
        mean_lat = float(np.mean(latencies)) if latencies else 0.0
        p50_lat = float(np.percentile(latencies, 50)) if latencies else 0.0
        p99_lat = float(np.percentile(latencies, 99)) if latencies else 0.0

        return {
            "model_name": model_name or "All",
            "total_samples": total,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "fpr": fpr,
            "f1_score": f1,
            "latency_mean_us": mean_lat,
            "latency_p50_us": p50_lat,
            "latency_p99_us": p99_lat
        }

    def generate_summary(self):
        """Generates a comparison dictionary and Markdown report across all evaluated models."""
        models = sorted(list(set(r["model_name"] for r in self.records)))
        summary = {"run_id": self.run_id, "models": {}}

        for m in models:
            metrics = self.compute_model_metrics(model_name=m)
            summary["models"][m] = metrics

        # Generate Markdown Table
        md_lines = [
            f"# SDN DDoS Detection Comparative Benchmark Report",
            f"**Run ID**: `{self.run_id}` | **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"### Model Performance Comparison",
            f"| Model Architecture | Accuracy | Precision | Recall (TPR) | False Alarm (FPR) | F1-Score | Mean Latency | p99 Latency |",
            f"| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
        ]

        for m in models:
            stat = summary["models"][m]
            acc_str = f"{stat['accuracy']*100:.2f}%" if stat['total_samples'] > 0 else "N/A"
            prec_str = f"{stat['precision']*100:.2f}%" if stat['total_samples'] > 0 else "N/A"
            rec_str = f"{stat['recall']*100:.2f}%" if stat['total_samples'] > 0 else "N/A"
            fpr_str = f"{stat['fpr']*100:.2f}%" if stat['total_samples'] > 0 else "N/A"
            f1_str = f"{stat['f1_score']:.4f}" if stat['total_samples'] > 0 else "N/A"
            mean_l_str = f"{stat['latency_mean_us']:.1f} us"
            p99_l_str = f"{stat['latency_p99_us']:.1f} us"

            md_lines.append(
                f"| **{m}** | {acc_str} | {prec_str} | {rec_str} | {fpr_str} | {f1_str} | {mean_l_str} | {p99_l_str} |"
            )

        md_content = "\n".join(md_lines) + "\n"

        # Save Markdown and JSON reports
        md_path = os.path.join(self.log_dir, f"benchmark_summary_{self.run_id}.md")
        json_path = os.path.join(self.log_dir, f"benchmark_summary_{self.run_id}.json")

        with open(md_path, "w") as f:
            f.write(md_content)

        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)

        return summary, md_content
