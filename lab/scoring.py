"""
Model scoring interface for live OpenFlow flow telemetry.
Provides predict_ddos_prob(X) returning [P(Benign), P(DDoS)] probabilities.
"""

import os
import json
import numpy as np

_MODEL = None
_SCALER_MAX = None

def _get_model_path():
    env_path = os.environ.get("DDOS_MODEL_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    candidates = [
        "model_ported.keras",
        "lab/model_ported.keras",
        "../model_ported.keras",
        "/home/mininet/project/model_ported.keras"
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "/home/mininet/project/model_ported.keras"

def _get_scaler_path():
    env_path = os.environ.get("DDOS_SCALER_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    candidates = [
        "scaler_params.json",
        "lab/scaler_params.json",
        "../scaler_params.json",
        "/home/mininet/project/scaler_params.json"
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "/home/mininet/project/scaler_params.json"

def load_scaler(scaler_path=None):
    global _SCALER_MAX
    if _SCALER_MAX is not None:
        return _SCALER_MAX

    path = scaler_path or _get_scaler_path()
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    _SCALER_MAX = np.array(data, dtype=np.float32)
                elif isinstance(data, dict) and "max" in data:
                    _SCALER_MAX = np.array(data["max"], dtype=np.float32)
                return _SCALER_MAX
        except Exception as e:
            print(f"[warning] Failed to load scaler from {path}: {e}")
    else:
        # Expected until Said exports the scaler max values from training
        pass

    return None

def load_model(model_path=None):
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    path = model_path or _get_model_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model not found at {path}. Run port_weights.py first.")

    import tensorflow as tf
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
    _MODEL = tf.keras.models.load_model(path, compile=False)
    return _MODEL

def softmax(logits):
    """Numerically stable softmax over the last axis."""
    exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
    return exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

def predict_ddos_prob(X):
    """
    Predict DDoS probability for an array of feature vectors.
    
    Parameters:
        X (np.ndarray): 2D array of shape (N, num_features). Expected shape (N, 84).
        
    Returns:
        np.ndarray: Probabilities of shape (N, 2), where:
                    column 0 = P(Benign)
                    column 1 = P(DDoS)
    """
    X_arr = np.asarray(X, dtype=np.float32)
    if X_arr.ndim == 1:
        X_arr = np.expand_dims(X_arr, axis=0)
        
    # Apply normalization if scaler parameters are available
    scaler_max = load_scaler()
    if scaler_max is not None:
        # Prevent division by zero
        safe_max = np.where(scaler_max == 0, 1.0, scaler_max)
        X_norm = np.where(scaler_max == 0, 0.0, X_arr / safe_max)
    else:
        X_norm = X_arr
        
    model = load_model()
    # Predict raw logits (model has 10 outputs; index 0 = Benign, index 1 = DDoS)
    raw_logits = model(X_norm, training=False).numpy()
    
    # Slice active binary classes (0 = Benign, 1 = DDoS)
    logits_01 = raw_logits[:, :2]
    
    # Convert active logits to normalized binary probabilities
    probs = softmax(logits_01)
    return probs

def is_ddos(X, threshold=0.5):
    """
    Predict binary DDoS flag for given features.
    
    Returns:
        np.ndarray of booleans (True = DDoS attack detected).
    """
    probs = predict_ddos_prob(X)
    return probs[:, 1] >= threshold
