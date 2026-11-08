#!/bin/bash
# check_env.sh: Non-destructive environment check for SDN DDoS lab.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${LAB_DIR:-$SCRIPT_DIR}"
VENV_PY="${VENV_PY:-/home/mininet/project/venv/bin/python3}"

# Fallback if venv is relative to project
if [ ! -f "$VENV_PY" ] && [ -f "$PROJECT_DIR/venv/bin/python3" ]; then
    VENV_PY="$PROJECT_DIR/venv/bin/python3"
fi

echo "=== Running DDoS Lab Environment Verification ==="

echo ""
echo "[1/6] System & tool versions"
uname -a
python3 --version
sudo mn --version
ovs-vsctl --version
hping3 --version | head -n 1
tcpdump --version | head -n 1
tshark -v | head -n 1
iperf3 -v | head -n 1

echo ""
echo "[2/6] Mininet baseline reachability"
sudo mn -c >/dev/null 2>&1
sudo mn --test pingall
sudo mn -c >/dev/null 2>&1

echo ""
echo "[3/6] POX controller (OpenFlow 1.0) & switch connection"
sudo pkill -9 -f pox >/dev/null 2>&1 || true
python3 /home/mininet/pox/pox.py forwarding.l2_learning > /tmp/pox_check.log 2>&1 &
POX_PID=$!
sleep 2

sudo mn --topo single,4 --controller remote,ip=127.0.0.1,port=6633 --test pingall
kill -TERM $POX_PID 2>/dev/null || sudo pkill -9 -f pox >/dev/null 2>&1 || true
sudo mn -c >/dev/null 2>&1

echo ""
echo "[4/6] Python venv, weight parity & scoring interface"
"$VENV_PY" -c "
import tensorflow as tf
import keras
import numpy as np
import pandas as pd
import sklearn
import scapy
print('ML environment libraries loaded:')
print(f'  TensorFlow: {tf.__version__}')
print(f'  Keras:      {keras.__version__}')
print(f'  NumPy:      {np.__version__}')
print(f'  Pandas:     {pd.__version__}')
print(f'  Scikit-L:   {sklearn.__version__}')
"

echo "Checking model weight parity against model_v1..."
"$VENV_PY" "$PROJECT_DIR/port_weights.py"

echo "Checking scoring interface..."
"$VENV_PY" "$PROJECT_DIR/test_scoring.py"

echo ""
echo "[5/6] POX component compilation (ddos_lab.py)"
POX_EXT="/home/mininet/pox/ext/ddos_lab.py"
if [ ! -f "$POX_EXT" ] && [ -f "$PROJECT_DIR/ddos_lab.py" ]; then
    cp "$PROJECT_DIR/ddos_lab.py" "$POX_EXT"
fi
python3 -m py_compile "$POX_EXT"
echo "Component compiled cleanly."

echo ""
echo "[6/6] Packet captures"
CAPTURES_DIR="$PROJECT_DIR/captures"
if [ ! -d "$CAPTURES_DIR" ] && [ -d "/home/mininet/project/captures" ]; then
    CAPTURES_DIR="/home/mininet/project/captures"
fi
ls -lh "$CAPTURES_DIR/benign_60s.pcap" "$CAPTURES_DIR/attack_30s.pcap"
tshark -r "$CAPTURES_DIR/benign_60s.pcap" -c 2
tshark -r "$CAPTURES_DIR/attack_30s.pcap" -c 2

echo ""
echo "=== All environment checks passed cleanly ==="
