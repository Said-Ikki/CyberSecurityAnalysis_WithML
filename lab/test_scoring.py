#!/usr/bin/env python3
"""
test_scoring.py - Unit test for scoring.py
"""

import numpy as np
import scoring

def main():
    print("Testing scoring.py inference...")
    
    # 5 random samples
    X = np.random.rand(5, 84).astype(np.float32)
    probs = scoring.predict_ddos_prob(X)
    flags = scoring.is_ddos(X, threshold=0.5)
    
    print(f"Output shape: {probs.shape} (Expected: (5, 2))")
    assert probs.shape == (5, 2), f"Unexpected shape {probs.shape}"
    
    # Check probability sum
    sums = np.sum(probs, axis=1)
    print(f"Row probability sums: {sums}")
    assert np.allclose(sums, 1.0, atol=1e-5), "Probabilities do not sum to 1.0"
    
    print("\nSample Probabilities [P(Benign), P(DDoS)]:")
    for i in range(len(probs)):
        print(f"  Sample {i}: P(Benign)={probs[i, 0]:.4f}, P(DDoS)={probs[i, 1]:.4f} -> is_ddos={flags[i]}")
        
    print("\nAll scoring unit tests passed successfully!")

if __name__ == "__main__":
    main()
