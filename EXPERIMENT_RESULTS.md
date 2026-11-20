# SDN DDoS Detection - Averaged Testing Results (n = 10 Runs per Model)

Aggregated results across the three 12-feature models (`ann`, `paper_cnn`, and `custom_cnn`) in the Mininet/POX testbed.

- **Environment**: Mininet 2.3.0, Open vSwitch 2.13.1, POX 0.7.0 (OpenFlow 1.0)
- **Live Test Setup**: 10 runs per model (30 runs total: initial 3 runs + 7 additional runs). Each run executes baseline traffic (iperf3 + HTTP + ping), a 15-second spoofed SYN flood (`hping3 --flood -S -p 80 --rand-source 10.0.0.2`), and a post-attack check with drop-rule mitigation enabled.
- **Statistical Tests**: Two-sided Welch's t-test and Mann-Whitney U test ($\alpha = 0.05$) for continuous/count metrics; two-sided Fisher's exact test for offline false positive rates.

---

## 1. Live Mininet Experiment (Mean +/- SD, n = 10 Runs per Model)

| Model | Baseline RTT | Baseline Pkt-In | Attack RTT* | Attack Loss | Attack Pkt-In | Alerts | Drop Rules |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **ann** (`model_v1.pt`) | 0.095 +/- 0.021 ms | 7.1 +/- 1.6 /s | 2.874 +/- 7.794 ms (med 0.301) | 20.0 +/- 32.7% | 3,101.6 +/- 93.9 /s | 2.8 +/- 1.3 | 1.5 +/- 0.5 |
| **paper_cnn** (`model_paper_v1.pt`) | 0.081 +/- 0.034 ms | 7.2 +/- 1.5 /s | 0.778 +/- 1.332 ms (med 0.045) | 10.0 +/- 31.6% | 3,219.2 +/- 189.9 /s | 4.8 +/- 2.3 | 4.3 +/- 2.5 |
| **custom_cnn** (`model_cnn_v1.pt`) | 0.080 +/- 0.016 ms | 7.3 +/- 1.5 /s | 3.350 +/- 7.047 ms (med 0.053) | 36.0 +/- 40.9% | 3,331.3 +/- 310.0 /s | 6.1 +/- 2.6 | 5.8 +/- 2.5 |

*\*1 run each for `paper_cnn` and `custom_cnn` experienced 100% ping loss during the flood, so Attack RTT is computed over n = 9 for those two models and n = 10 for `ann`.*

### Pairwise Statistical Significance (Live Mininet Metrics, n = 10)

| Metric | Comparison | Welch's t | Welch p-value | Mann-Whitney p-value | Significant (p < 0.05) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Alerts Triggered** | ann vs paper_cnn | -2.425 | 0.0289 | 0.0287 | Yes |
| | ann vs custom_cnn | -3.627 | 0.0029 | 0.0032 | Yes |
| | paper_cnn vs custom_cnn | -1.206 | 0.2435 | 0.0960 | No |
| **Drop Rules Installed** | ann vs paper_cnn | -3.470 | 0.0062 | 0.0021 | Yes |
| | ann vs custom_cnn | -5.352 | 0.0003 | 0.0011 | Yes |
| | paper_cnn vs custom_cnn | -1.346 | 0.1949 | 0.1001 | No |
| **Attack Pkt-In Rate** | ann vs paper_cnn | -1.755 | 0.1025 | 0.1620 | No |
| | ann vs custom_cnn | -2.243 | 0.0473 | 0.2123 | Welch only |
| | paper_cnn vs custom_cnn | -0.975 | 0.3450 | 0.9699 | No |
| **Attack Packet Loss** | ann vs paper_cnn | 0.696 | 0.4956 | 0.3867 | No |
| | ann vs custom_cnn | -0.967 | 0.3470 | 0.3461 | No |
| | paper_cnn vs custom_cnn | -1.591 | 0.1301 | 0.1025 | No |
| **Attack RTT** | ann vs paper_cnn | 0.837 | 0.4232 | 0.4622 | No |
| | ann vs custom_cnn | -0.140 | 0.8903 | 0.5134 | No |
| | paper_cnn vs custom_cnn | -1.076 | 0.3113 | 0.8946 | No |
| **Baseline RTT (control)** | ann vs paper_cnn | 1.071 | 0.3011 | 0.0890 | No |
| | ann vs custom_cnn | 1.738 | 0.1006 | 0.1733 | No |
| | paper_cnn vs custom_cnn | 0.093 | 0.9277 | 0.5962 | No |

**Notes:**
- Baseline RTT and baseline packet-in rates show no significant differences across models (all p > 0.08), confirming consistent testbed conditions across all 30 runs.
- Both CNNs trigger significantly more alerts and install significantly more drop rules than the ANN (p < 0.03 for `paper_cnn`, p < 0.004 for `custom_cnn`), driven by higher false-positive triggering on benign/mixed traffic.
- Under-attack RTT and packet loss do not differ significantly between models (p > 0.10) because `hping3 --rand-source` spoofs a new source IP per packet, saturating the OpenFlow 1.0 control channel (~3,100–3,300 pkts/s) regardless of per-IP drop rules.

---

## 2. CPU Inference Latency & Throughput (n = 200 Runs per Model)

| Model | Mean +/- SD | Median (p50) | p99 Latency | Est. Max Throughput |
| :--- | :---: | :---: | :---: | :---: |
| **ann** (`model_v1.pt`) | 47.6 +/- 21.7 us | 44.4 us | 85.0 us | 21,008 flows/s |
| **custom_cnn** (`model_cnn_v1.pt`) | 226.0 +/- 49.2 us | 210.2 us | 514.0 us | 4,425 flows/s |
| **paper_cnn** (`model_paper_v1.pt`) | 237.7 +/- 49.1 us | 222.4 us | 499.3 us | 4,207 flows/s |

### Pairwise Statistical Significance (CPU Inference Latency, n = 200)

| Comparison | Welch's t | Welch p-value | Mann-Whitney p-value | Significant (p < 0.05) |
| :--- | :---: | :---: | :---: | :---: |
| ann vs paper_cnn | -50.07 | 8.69e-140 | 8.63e-66 | Yes (ANN 5.0x faster) |
| ann vs custom_cnn | -46.91 | 8.97e-133 | 8.89e-66 | Yes (ANN 4.7x faster) |
| paper_cnn vs custom_cnn | 2.38 | 0.0177 | 1.54e-23 | Yes |

---

## 3. Offline PCAP Flow Benchmark (90 Windows: 70 Benign, 20 Attack)

| Model | Accuracy | Precision | Recall (TPR) | False Positive Rate | F1-Score | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **ann** (`model_v1.pt`) | 62.22% | 0.00% | 0.00% | 20.00% (14/70) | 0.0000 | 88.6 us |
| **paper_cnn** (`model_paper_v1.pt`) | 34.44% | 25.32% | 100.00% | 84.29% (59/70) | 0.4040 | 283.3 us |
| **custom_cnn** (`model_cnn_v1.pt`) | 27.78% | 23.53% | 100.00% | 92.86% (65/70) | 0.3810 | 270.5 us |

### Pairwise Statistical Significance (Benign False Positive Rate, n = 70, Fisher's Exact)

| Comparison | Benign FPR | Fisher's Exact p-value | Significant (p < 0.05) |
| :--- | :---: | :---: | :---: |
| ann vs paper_cnn | 20.0% vs 84.3% | 1.06e-14 | Yes |
| ann vs custom_cnn | 20.0% vs 92.9% | 1.61e-19 | Yes |
| paper_cnn vs custom_cnn | 84.3% vs 92.9% | 0.1829 | No |

---

## 4. Training / Validation Reference (Kaggle Balanced Dataset)

From `ANN_Torch_CSML.ipynb`:

| Model | Validation Accuracy | Validation Loss |
| :--- | :---: | :---: |
| **ann** (`model_v1.pt`) | 96.32% | 0.0929 |
| **paper_cnn** (`model_paper_v1.pt`) | 93.41% | 0.1597 |
| **custom_cnn** (`model_cnn_v1.pt`) | ~90% | — |
