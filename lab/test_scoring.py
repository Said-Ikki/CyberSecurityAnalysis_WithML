#!/usr/bin/env python3
"""
test_scoring.py - Unit test and validation suite for multi-model scoring.py
"""

import numpy as np
import scoring

def main():
    print("=== Testing Multi-Model scoring.py ===")
    
    # Check scaler loading
    scaler = scoring.load_scaler()
    print(f"Scaler loaded: {scaler is not None}")
    if scaler is not None:
        print(f"Scaler shape: {scaler.shape} (Expected: (12,))")
        assert len(scaler) == 12, "Scaler must have 12 values"
        print(f"Scaler sample values: {scaler[:4]} ... {scaler[-2:]}")

    # Test each model
    models = ['ann', 'paper_cnn', 'custom_cnn']
    X = np.random.rand(5, 12).astype(np.float32)

    for m in models:
        print(f"\n--- Testing Model: {m} ---")
        probs = scoring.predict_ddos_prob(X, model_name=m)
        flags = scoring.is_ddos(X, threshold=0.5, model_name=m)

        print(f"Output shape: {probs.shape} (Expected: (5, 2))")
        assert probs.shape == (5, 2), f"Shape mismatch: {probs.shape}"

        # Probability sum check
        sums = np.sum(probs, axis=1)
        print(f"Row probability sums: {sums}")
        assert np.allclose(sums, 1.0, atol=1e-5), "Probabilities do not sum to 1.0"

        # Check sample outputs
        for i in range(min(2, len(probs))):
            print(f"  Sample {i}: P(Benign)={probs[i, 0]:.4f}, P(DDoS)={probs[i, 1]:.4f} -> is_ddos={flags[i]}")

    print("\n--- Benchmarking Inference Latency Across Models (50 runs) ---")
    single_sample = X[0:1]
    latencies = scoring.benchmark_inference(single_sample, num_runs=50)
    print(f"{'Model':<15} | {'Mean Latency':<15} | {'p50':<12} | {'p99':<12}")
    print("-" * 60)
    for m, stat in latencies.items():
        print(f"{m:<15} | {stat['mean_us']:.1f} us        | {stat['p50_us']:.1f} us    | {stat['p99_us']:.1f} us")

    print("\nAll multi-model unit tests passed successfully!")

if __name__ == "__main__":
    main()
