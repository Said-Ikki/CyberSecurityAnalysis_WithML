# SDN DDoS Lab Environment

This directory contains the Mininet network topology, POX OpenFlow controller, and experiment scripts for our Advanced Computer Networks DDoS project (simulating the Najar & Naik 2024 testbed).

## What's in `lab/`

- `topo.py`: Mininet single-switch topology (4 hosts: `h1` attacker, `h2` victim server, `h3`/`h4` benign users).
- `ddos_lab.py`: POX controller component (L2 learning switch + flow stats polling every 5s + packet-in logging).
- `test_flow_stats.py`: Quick test checking that the controller receives flow statistics from switch `s1`.
- `run_experiment.py`: Experiment running baseline traffic, a spoofed SYN flood, and post-attack recovery.
- `capture_traffic.py`: Captures benign and attack `.pcap` files on the victim's switch port (`s1-eth2`).
- `check_env.sh`: Non-destructive verification script that checks the environment and runs the test suite.
- `port_weights.py` & `scoring.py`: Model loader and real-time inference scoring interface for live flow stats.

## How to Set Up and Test Mininet (If You Want to Run It Yourself)

If you'd like to spin up the environment and run the tests locally:

1. **Get the Mininet VM**:
   - Download the official Mininet 2.3.0 VM image (Ubuntu 20.04 LTS) from [mininet.org/download](http://mininet.org/download/).
   - Import the `.ova` into VirtualBox (or VMware) with 2+ CPU cores and 4GB+ RAM.
   - In VirtualBox network settings for the VM, set Adapter 1 to NAT, click Advanced -> Port Forwarding, and add:
     - `Host Port: 2222` -> `Guest Port: 22`
   - Start the VM and SSH in (default user/pass is `mininet` / `mininet`):
     ```bash
     ssh -p 2222 mininet@127.0.0.1
     ```

2. **Install Required Packages**:
   Inside the VM, install the networking tools:
   ```bash
   sudo apt-get update
   sudo apt-get install -y hping3 tcpdump tshark iperf3 git python3-venv
   ```

3. **Install POX**:
   Mininet VMs usually come with POX pre-cloned in `~/pox`. If not:
   ```bash
   git clone https://github.com/noxrepo/pox.git ~/pox
   cd ~/pox && git checkout gar-experimental
   ```
   Copy our controller component into POX's extension folder:
   ```bash
   cp lab/ddos_lab.py ~/pox/ext/
   ```

## Running the Lab

All experiment commands need root privileges because Mininet creates virtual network namespaces.

### 1. Start the Controller
In one terminal, start POX with our component:
```bash
python3 ~/pox/pox.py ddos_lab 2>&1 | tee pox_ddos_lab.log
```

### 2. Run the Verification Check
In a second terminal, run the non-destructive check:
```bash
cd lab
./check_env.sh
```
This tests switch connectivity, OpenFlow 1.0 packet handling, model weight parity, and packet captures.

### 3. Run the Flood Experiment
To see the traffic flood in action:
```bash
cd lab
sudo python3 run_experiment.py
```
This generates baseline HTTP/iperf traffic, launches a 15-second spoofed SYN flood from `h1` (`hping3 --flood -S -p 80 --rand-source 10.0.0.2`), and measures packet-in spikes at the controller.

To clean up Mininet between runs:
```bash
sudo mn -c
```
