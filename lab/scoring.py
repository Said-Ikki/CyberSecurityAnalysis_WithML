"""
Model scoring interface for live OpenFlow flow telemetry.
Supports all three 12-feature trained architectures:
  - 'ann': DeepNeuralNet (model_v1.pt, ~95% Acc)
  - 'paper_cnn': Najar et al. 2024 Conv1D (model_paper_v1.pt, ~90% Acc)
  - 'custom_cnn': Said Custom Conv1D (model_cnn_v1.pt, ~90% Acc)

Automatically applies max-normalization from max_of_each_column.txt.
Runs pure NumPy inference for sub-millisecond real-time controller execution.
"""

import os
import json
import time
import zipfile
import pickle
import io
import numpy as np

# Global weight caches
_WEIGHTS = {}
_SCALER_MAX = None

MODEL_FILES = {
    'ann': 'model_v1.pt',
    'paper_cnn': 'model_paper_v1.pt',
    'custom_cnn': 'model_cnn_v1.pt'
}

def _find_file(filename):
    candidates = [
        filename,
        os.path.join(os.path.dirname(__file__), filename),
        os.path.join(os.path.dirname(__file__), '..', filename),
        os.path.join('lab', filename),
        os.path.join('..', filename),
        os.path.join('partner_repo', filename),
        os.path.join('..', 'partner_repo', filename),
        os.path.join('/home/mininet/project/partner_repo', filename),
        os.path.join('/home/mininet/project', filename),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return os.path.abspath(c)
    return None

def load_scaler(scaler_path=None):
    """Loads 12 max values for normalization from max_of_each_column.txt or scaler_params.json."""
    global _SCALER_MAX
    if _SCALER_MAX is not None:
        return _SCALER_MAX

    path = scaler_path or _find_file("max_of_each_column.txt") or _find_file("scaler_params.json")
    if path and os.path.exists(path):
        try:
            if path.endswith(".txt"):
                vals = []
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            vals.append(float(line))
                if len(vals) == 12:
                    _SCALER_MAX = np.array(vals, dtype=np.float32)
            else:
                with open(path, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        _SCALER_MAX = np.array(data, dtype=np.float32)
                    elif isinstance(data, dict) and "max" in data:
                        _SCALER_MAX = np.array(data["max"], dtype=np.float32)
        except Exception as e:
            print(f"[warning] Failed to load scaler from {path}: {e}")

    return _SCALER_MAX

def _extract_weights_from_pt(path, prefix):
    """Extracts float32 weights from PyTorch zip serialization archive without torch."""
    with zipfile.ZipFile(path, 'r') as z:
        storages = {}
        for name in z.namelist():
            if name.startswith(prefix + '/data/'):
                idx = name.split('/')[-1]
                raw = z.read(name)
                storages[idx] = np.frombuffer(raw, dtype=np.float32)

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
                elif module == '__main__':
                    class DynamicClass:
                        def __init__(self, *args, **kwargs):
                            self._name = name
                    return DynamicClass
                try:
                    return super().find_class(module, name)
                except Exception:
                    class Dummy:
                        def __init__(self, *args, **kwargs): pass
                    return Dummy

            def persistent_load(self, pid):
                return storages[str(pid[2])]

        pkl_bytes = z.read(prefix + '/data.pkl')
        unpickler = MockUnpickler(io.BytesIO(pkl_bytes))
        obj = unpickler.load()

        weights = {}
        for m_name, m in obj._modules.items():
            if hasattr(m, '_parameters'):
                for p_name, p in m._parameters.items():
                    if p is not None:
                        weights[f'{m_name}.{p_name}'] = p

    return weights

def load_weights(model_name='ann'):
    """Loads weights for the specified model ('ann', 'paper_cnn', 'custom_cnn')."""
    global _WEIGHTS
    if model_name in _WEIGHTS:
        return _WEIGHTS[model_name]

    filename = MODEL_FILES.get(model_name)
    if not filename:
        raise ValueError(f"Unknown model name: {model_name}. Choose from: {list(MODEL_FILES.keys())}")

    path = _find_file(filename)
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Model file {filename} for {model_name} not found.")

    prefix = filename.replace('.pt', '')
    weights = _extract_weights_from_pt(path, prefix)
    _WEIGHTS[model_name] = weights
    return weights

def relu(x):
    return np.maximum(0, x)

def softmax(logits):
    exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
    return exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

def conv1d_valid(x, w, b):
    # x: (N, C_in, L_in), w: (C_out, C_in, K), b: (C_out,)
    N, C_in, L_in = x.shape
    C_out, _, K = w.shape
    L_out = L_in - K + 1
    out = np.zeros((N, C_out, L_out), dtype=np.float32)
    for k in range(K):
        out += np.tensordot(x[:, :, k:k+L_out], w[:, :, k], axes=([1], [1])).transpose(0, 2, 1)
    return out + b[np.newaxis, :, np.newaxis]

def maxpool1d(x, pool_size, stride):
    N, C, L = x.shape
    L_out = (L - pool_size) // stride + 1
    out = np.zeros((N, C, L_out), dtype=np.float32)
    for i in range(L_out):
        start = i * stride
        out[:, :, i] = np.max(x[:, :, start:start+pool_size], axis=2)
    return out

def forward_ann(X, w):
    x1 = relu(np.dot(X, w['fc1.weight'].T) + w['fc1.bias'])
    x2 = relu(np.dot(x1, w['hid_1.weight'].T) + w['hid_1.bias'])
    x3 = relu(np.dot(x2, w['hid_2.weight'].T) + w['hid_2.bias'])
    x4 = relu(np.dot(x3, w['hid_3.weight'].T) + w['hid_3.bias'])
    return np.dot(x4, w['fc2.weight'].T) + w['fc2.bias']

def forward_paper_cnn(X, w):
    x = X[:, np.newaxis, :]  # (N, 1, 12)
    c1 = relu(conv1d_valid(x, w['cnn1.weight'], w['cnn1.bias']))
    m1 = maxpool1d(c1, 3, 2)
    c2 = relu(conv1d_valid(m1, w['cnn2.weight'], w['cnn2.bias']))
    m2 = maxpool1d(c2, 2, 2)
    flat = m2.reshape(X.shape[0], -1)
    h2 = relu(np.dot(flat, w['hid_2.weight'].T) + w['hid_2.bias'])
    h3 = relu(np.dot(h2, w['hid_3.weight'].T) + w['hid_3.bias'])
    return np.dot(h3, w['fc2.weight'].T) + w['fc2.bias']

def forward_custom_cnn(X, w):
    x = X[:, np.newaxis, :]  # (N, 1, 12)
    c1 = relu(conv1d_valid(x, w['cnn1.weight'], w['cnn1.bias']))
    m1 = maxpool1d(c1, 3, 2)
    c2 = relu(conv1d_valid(m1, w['cnn2.weight'], w['cnn2.bias']))
    m2 = maxpool1d(c2, 2, 2)
    flat = m2.reshape(X.shape[0], -1)
    fc1 = relu(np.dot(flat, w['fc1.weight'].T) + w['fc1.bias'])
    h1 = relu(np.dot(fc1, w['hid_1.weight'].T) + w['hid_1.bias'])
    h2 = relu(np.dot(h1, w['hid_2.weight'].T) + w['hid_2.bias'])
    h3 = relu(np.dot(h2, w['hid_3.weight'].T) + w['hid_3.bias'])
    return np.dot(h3, w['fc2.weight'].T) + w['fc2.bias']

def normalize_features(X):
    X_arr = np.asarray(X, dtype=np.float32)
    if X_arr.ndim == 1:
        X_arr = np.expand_dims(X_arr, axis=0)

    scaler_max = load_scaler()
    if scaler_max is not None and len(scaler_max) == X_arr.shape[1]:
        safe_max = np.where(scaler_max == 0, 1.0, scaler_max)
        X_norm = np.where(scaler_max == 0, 0.0, X_arr / safe_max)
    else:
        X_norm = X_arr

    return X_norm

def predict_ddos_prob(X, model_name=None):
    """
    Predict DDoS probability for an array of 12-feature vectors.

    Parameters:
        X (np.ndarray): Shape (N, 12) or (12,)
        model_name (str): 'ann' | 'paper_cnn' | 'custom_cnn' (defaults to DDOS_MODEL_TYPE env or 'ann')

    Returns:
        np.ndarray: Probabilities of shape (N, 2), where:
                    column 0 = P(Benign)
                    column 1 = P(DDoS)
    """
    model_name = model_name or os.environ.get("DDOS_MODEL_TYPE", "ann")
    w = load_weights(model_name)
    X_norm = normalize_features(X)

    if model_name == 'ann':
        logits = forward_ann(X_norm, w)
    elif model_name == 'paper_cnn':
        logits = forward_paper_cnn(X_norm, w)
    elif model_name == 'custom_cnn':
        logits = forward_custom_cnn(X_norm, w)
    else:
        raise ValueError(f"Unknown model_name: {model_name}")

    # Slice binary active classes (2 outputs)
    logits_01 = logits[:, :2]
    return softmax(logits_01)

def is_ddos(X, threshold=0.5, model_name=None):
    """Predict binary DDoS flag for given features (True = DDoS attack detected)."""
    probs = predict_ddos_prob(X, model_name=model_name)
    return probs[:, 1] >= threshold

def benchmark_inference(X, num_runs=50):
    """Benchmarks per-sample inference latency across all three models."""
    results = {}
    for name in ['ann', 'paper_cnn', 'custom_cnn']:
        # Warmup
        _ = predict_ddos_prob(X, model_name=name)
        latencies = []
        for _ in range(num_runs):
            t0 = time.perf_counter()
            _ = predict_ddos_prob(X, model_name=name)
            latencies.append((time.perf_counter() - t0) * 1e6)  # microseconds
        results[name] = {
            'mean_us': float(np.mean(latencies)),
            'p50_us': float(np.percentile(latencies, 50)),
            'p99_us': float(np.percentile(latencies, 99))
        }
    return results
