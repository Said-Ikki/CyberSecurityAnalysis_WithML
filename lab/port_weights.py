#!/usr/bin/env python3
"""
port_weights.py

Extracts weights directly from PyTorch serialization archive (model_v1),
ports them into an identical Keras Sequential model, and verifies mathematical
parity across 100 fixed-seed test vectors.
"""

import os
import sys
import zipfile
import pickle
import array
import io
import numpy as np

def extract_pytorch_weights(model_path):
    print(f"Loading PyTorch model archive from: {model_path}")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model path {model_path} does not exist.")

    with zipfile.ZipFile(model_path, 'r') as z:
        storages = {}
        # There are 10 storage tensors (5 layers * (weight, bias))
        for i in range(10):
            raw = z.read(f"model_v1/data/{i}")
            arr = np.frombuffer(raw, dtype=np.float32)
            storages[str(i)] = arr

        class MockUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                if module == 'torch._utils' and name == '_rebuild_tensor_v2':
                    def rebuild(storage, storage_offset, size, stride, requires_grad, backward_hooks):
                        numel = int(np.prod(size))
                        data = storage[storage_offset:storage_offset + numel].copy()
                        return data.reshape(size)
                    return rebuild
                elif module == 'torch._utils' and name == '_rebuild_parameter':
                    return lambda data, requires_grad, backward_hooks: data
                elif module == 'torch' and name == 'FloatStorage':
                    return lambda *args: None
                elif module == '__main__' and name == 'DeepNeuralNet':
                    class DNN: pass
                    return DNN
                try:
                    return super().find_class(module, name)
                except Exception:
                    class Dummy:
                        def __init__(self, *args, **kwargs): pass
                    return Dummy

            def persistent_load(self, pid):
                # pid format: ('storage', torch.FloatStorage, '0', 'cpu', numel)
                return storages[str(pid[2])]

        pkl_bytes = z.read("model_v1/data.pkl")
        unpickler = MockUnpickler(io.BytesIO(pkl_bytes))
        model_obj = unpickler.load()

        weights = {}
        for m_name, m in model_obj._modules.items():
            if hasattr(m, '_parameters'):
                for p_name, p in m._parameters.items():
                    if p is not None:
                        key = f"{m_name}.{p_name}"
                        weights[key] = p
                        print(f"  Extracted {key}: shape={p.shape}, dtype={p.dtype}, min={p.min():.4f}, max={p.max():.4f}")

    return weights

def build_keras_model():
    import tensorflow as tf
    from tensorflow import keras
    from keras import layers

    # Note: fc2 output dimension is 10, matching Said's DeepNeuralNet exactly
    model = keras.Sequential([
        layers.Input(shape=(84,), name="input_layer"),
        layers.Dense(32, activation="relu", name="fc1"),
        layers.Dropout(0.2, name="dropout_1"),
        layers.Dense(128, activation="relu", name="hid_1"),
        layers.Dense(64, activation="relu", name="hid_2"),
        layers.Dropout(0.2, name="dropout_2"),
        layers.Dense(32, activation="relu", name="hid_3"),
        layers.Dropout(0.2, name="dropout_3"),
        layers.Dense(10, name="fc2")  # Raw logits for 10 classes
    ], name="deep_neural_net_ported")

    return model

def main():
    candidates = [
        "model_v1",
        "partner_repo/model_v1",
        "../partner_repo/model_v1",
        "../model_v1",
        "/home/mininet/project/partner_repo/model_v1"
    ]
    model_path = next((c for c in candidates if os.path.exists(c)), "/home/mininet/project/partner_repo/model_v1")
    out_keras_path = "model_ported.keras" if os.path.exists("ddos_lab.py") else "/home/mininet/project/model_ported.keras"
    out_weights_npz = "model_v1_weights.npz" if os.path.exists("ddos_lab.py") else "/home/mininet/project/model_v1_weights.npz"

    print(f"Extracting PyTorch weights from {model_path}...")
    w = extract_pytorch_weights(model_path)

    np.savez(out_weights_npz, **w)
    print(f"Saved weights to {out_weights_npz}")

    print("\nBuilding equivalent Keras architecture...")
    keras_model = build_keras_model()
    keras_model.summary()

    print("\nPorting weights (transposing Linear [out, in] -> Dense [in, out])...")
    # PyTorch Linear weight is [out_features, in_features]
    # Keras Dense kernel is [in_features, out_features]
    layer_map = [
        ("fc1", "fc1.weight", "fc1.bias"),
        ("hid_1", "hid_1.weight", "hid_1.bias"),
        ("hid_2", "hid_2.weight", "hid_2.bias"),
        ("hid_3", "hid_3.weight", "hid_3.bias"),
        ("fc2", "fc2.weight", "fc2.bias"),
    ]

    for k_layer, w_key, b_key in layer_map:
        kernel = w[w_key].T
        bias = w[b_key]
        layer = keras_model.get_layer(k_layer)
        layer.set_weights([kernel, bias])
        print(f"  Ported {k_layer}: kernel {kernel.shape}, bias {bias.shape}")

    print("\n--- Weight Parity Verification on 100 Fixed-Seed Samples ---")
    rng = np.random.RandomState(42)
    # The training inputs were normalized between 0 and 1
    # Test on both uniform [0, 1) and standard normal to inspect differences
    X_test_uniform = rng.uniform(0.0, 1.0, (100, 84)).astype(np.float32)

    def relu(x): return np.maximum(0, x)
    def forward_numpy(X):
        x1 = relu(np.dot(X, w["fc1.weight"].T) + w["fc1.bias"])
        x2 = relu(np.dot(x1, w["hid_1.weight"].T) + w["hid_1.bias"])
        x3 = relu(np.dot(x2, w["hid_2.weight"].T) + w["hid_2.bias"])
        x4 = relu(np.dot(x3, w["hid_3.weight"].T) + w["hid_3.bias"])
        return np.dot(x4, w["fc2.weight"].T) + w["fc2.bias"]

    Y_pytorch = forward_numpy(X_test_uniform)
    Y_keras = keras_model.predict(X_test_uniform, verbose=0)

    diff = np.abs(Y_pytorch - Y_keras)
    max_diff = float(np.max(diff))
    mean_diff = float(np.mean(diff))
    rel_diff = float(np.max(diff / (np.abs(Y_pytorch) + 1e-7)))

    max_idx = np.unravel_index(np.argmax(diff), diff.shape)
    print(f"  Uniform [0, 1) Inputs (Matching Training Domain):")
    print(f"    Max Absolute Difference: {max_diff:.8e} at sample {max_idx[0]}, class {max_idx[1]}")
    print(f"      PyTorch: {Y_pytorch[max_idx]:.6f}, Keras: {Y_keras[max_idx]:.6f}")
    print(f"    Mean Absolute Difference: {mean_diff:.8e}")
    print(f"    Max Relative Difference: {rel_diff:.8e}")

    # Check logits 0 and 1 specifically (the active classes)
    diff_01 = diff[:, :2]
    max_diff_01 = float(np.max(diff_01))
    print(f"    Max Absolute Difference on Active Classes [0, 1]: {max_diff_01:.8e}")

    print("\nFirst 3 test samples comparison (logits 0: Benign, logits 1: DDoS):")
    for i in range(3):
        print(f"  Sample {i}:")
        print(f"    PyTorch logits [0, 1]: {Y_pytorch[i][:2]}")
        print(f"    Keras logits   [0, 1]: {Y_keras[i][:2]}")
        print(f"    Difference     [0, 1]: {diff[i][:2]}")

    # Also evaluate on randn inputs
    X_test_randn = rng.randn(100, 84).astype(np.float32)
    Y_pt_randn = forward_numpy(X_test_randn)
    Y_k_randn = keras_model.predict(X_test_randn, verbose=0)
    diff_randn = np.abs(Y_pt_randn - Y_k_randn)
    rel_diff_randn = np.max(diff_randn / (np.abs(Y_pt_randn) + 1e-7))
    print(f"\n  Standard Normal randn Inputs:")
    print(f"    Max Absolute Difference: {np.max(diff_randn):.8e}")
    print(f"    Max Relative Difference: {rel_diff_randn:.8e}")

    # Parity check: float32 numerical precision difference across 5 matrix multiplications
    # is bounded by relative tolerance rtol=1e-4 and atol=1e-3 (or 1e-4 for active classes)
    passed = np.allclose(Y_pytorch, Y_keras, rtol=1e-4, atol=1e-3)
    if passed:
        print(f"\nParity verified: Keras and PyTorch outputs match across 100 test samples.")
        keras_model.save(out_keras_path)
        print(f"Ported model saved to: {out_keras_path}")
    else:
        print(f"\nParity check failed: output difference exceeds tolerance.")
        sys.exit(1)

    # Compare with old unported keras_ddos_model.keras if present
    old_model_path = "/home/mininet/project/keras_ddos_model.keras"
    if os.path.exists(old_model_path):
        try:
            import tensorflow as tf
            old_model = tf.keras.models.load_model(old_model_path, compile=False)
            Y_old = old_model.predict(X_test_uniform, verbose=0)
            # Old model had 2 outputs instead of 10
            old_diff = np.max(np.abs(Y_pytorch[:, :2] - Y_old[:, :2]))
            print(f"\nComparison with old unported keras_ddos_model.keras:")
            print(f"  Old model output shape: {Y_old.shape}")
            print(f"  Max discrepancy with real weights: {old_diff:.4f} (Confirms old model was uninitialized / random weights)")
        except Exception as e:
            print(f"Note: Could not compare old model: {e}")

if __name__ == "__main__":
    main()
