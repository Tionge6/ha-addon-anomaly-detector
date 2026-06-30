# Home Assistant Addon Anomaly Detector

A lightweight, statistical runtime anomaly detection framework for Home Assistant Supervisor-managed add-ons. This is the proof-of-concept implementation accompanying the MSc thesis *"Home Assistant: Anomaly Detection in Supervisor Add-ons"* at Ss. Cyril and Methodius University, Skopje, North Macedonia.

> **Important:** This is a research prototype, not a production-ready security product. It was developed and evaluated in a controlled experimental environment. Use it with that understanding.

---

## What It Does

Home Assistant's Supervisor applies meaningful pre-installation checks before an add-on runs, but exercises no continuous monitoring of what it does at runtime. This framework fills that gap by:

- Collecting per-container CPU, memory, and network metrics via cAdvisor and Prometheus
- Building statistical baseline profiles for each monitored add-on over a 24-hour collection period
- Running a continuous 15-second detection loop comparing live readings against per-container thresholds
- Mapping detected anomalies to a five-phase incident response playbook with plain-language guidance for non-technical home users
- Writing alerts to a JSON log, a human-readable text file, and a push notification file

---

## Repository Structure

```
ha-addon-anomaly-detector/
├── src/
│   ├── baseline.py       # Builds per-container statistical profiles from CSV data
│   ├── detector.py       # 15-second detection loop with five signal types
│   ├── playbook.py       # Maps anomaly types to incident response guidance
│   ├── alerts.py         # Cooldown management and three-channel alert output
│   ├── run.sh            # Addon entrypoint script
│   ├── config.yaml       # Home Assistant addon configuration
│   └── Dockerfile        # Alpine Linux container definition
├── attacks/
│   ├── tier1/            # Resource abuse simulation (stress-ng)
│   ├── tier2/            # Network attack simulation (curl exfiltration + scan)
│   └── tier3/            # HA-specific attack simulation (forbidden access + API abuse)
├── prometheus/
│   └── prometheus.yml    # Prometheus scrape configuration
├── docs/
│   ├── reproducibility.md
│   └── installation.md
└── README.md
```

---

## Software Versions Used in Experiments

| Component | Version |
|-----------|---------|
| Home Assistant OS | 16.3 |
| Home Assistant Core | 2025.12.4 |
| Home Assistant Supervisor | 2026.06.2 |
| Python | 3.11 (Alpine) |
| cAdvisor | latest (gcr.io/cadvisor/cadvisor) |
| Prometheus | latest (docker) |
| VirtualBox | 7.x |
| Host OS | Windows 11 |

---

## Quick Start — Reproducing the Experiments

### 1. Set up the test environment

- Install VirtualBox and create a VM running Home Assistant OS
- Configure the VM with a bridged network adapter
- Note the VM's IP address from the HA console

### 2. Start cAdvisor inside the HA VM

Open the Terminal add-on in HA and run:

```bash
docker run -d \
  --name cadvisor \
  --restart always \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /sys:/sys:ro \
  -v /var/lib/docker/:/var/lib/docker:ro \
  gcr.io/cadvisor/cadvisor:latest
```

### 3. Start Prometheus on your host machine

Edit `prometheus/prometheus.yml` and replace `<HA_VM_IP>` with your VM's actual IP address. Then run:

```bash
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

Verify it is scraping by going to `http://localhost:9090/targets` — cAdvisor should show as UP.

### 4. Collect the baseline dataset

Run the baseline collection script on your host machine for 24 hours with only normal add-ons running. The script queries Prometheus and writes labelled CSV files to a local directory.

### 5. Build baseline profiles

Copy the CSV files to `/share/anomaly_detector/baseline/` on the HA VM via Samba, then run:

```bash
python baseline.py
```

This produces `baseline_profiles.json` at `/share/anomaly_detector/baseline_profiles.json`.

### 6. Install the detector add-on

Copy the `src/` directory to `/addons/anomaly_detector/` on the HA VM, then install it through the HA UI via Settings → Add-ons → Add-on Store → Local add-ons.

### 7. Run the attack simulations

Each malicious add-on in `attacks/` can be installed the same way as a local add-on. Run them one at a time with the detector active. Do not run two malicious add-ons simultaneously.

---

## Detection Signals

| Signal | Metric | Default Fallback Threshold |
|--------|--------|--------------------------|
| cpu\_spike | CPU usage rate | 50% (warning), 100% (critical) |
| memory\_spike | Memory consumption | 300 MB (warning), 600 MB (critical) |
| exfiltration | Network TX rate | 600 B/s (warning), 1000 B/s (critical) |
| network\_scan | Combined TX + RX elevation | 600 B/s TX and 600 B/s RX simultaneously |
| restart\_loop | Container heartbeat gaps | 3 missing (warning), 7 missing (critical) |
| combined\_attack | 3+ distinct signals within 5 minutes | CRITICAL escalation |

---

## Alert Outputs

Alerts are written to three locations on the HA VM:

| File | Description |
|------|-------------|
| `/share/anomaly_detector/alerts/alert_log.json` | Structured JSON log of all alerts |
| `/share/anomaly_detector/alerts/latest_alerts.txt` | Human-readable plain text output |
| `/share/anomaly_detector/alerts/notify.json` | Push notification file for HA automations |

---

## Known Limitations

- **Sandbox limitation:** The `ha` CLI binary is not available inside the add-on container, preventing log-based detection of Tier 3 HA-specific signals (forbidden file access, Supervisor API abuse). This is an architectural constraint of HA's extensibility model.
- **Hardware:** Experiments were conducted on a VirtualBox x86-64 VM. Behaviour on Raspberry Pi ARM hardware has not been validated.
- **Baseline period:** 24 hours may not capture weekly or seasonal usage patterns. A 7-14 day baseline is recommended for production use.
- **Attack realism:** The simulated attacks use simple, high-signal scripts. Sophisticated low-and-slow attacks may evade threshold-based detection.

---

## Experimental Results

| Tier | Attack Type | Detection Latency | Outcome |
|------|-------------|------------------|---------|
| Tier 1 | Resource Abuse (stress-ng) | 29 seconds | DETECTED — cpu\_spike, memory\_spike, restart\_loop, combined\_attack CRITICAL |
| Tier 2 | Network Attack (curl) | 107 seconds | DETECTED — exfiltration |
| Tier 3 | HA-Specific (forbidden access + API abuse) | 78 seconds | PARTIAL — network component detected, HA-specific signals not detectable from sandbox |

**False positive rate:** 0.1190% (24 false positives out of 20,160 total detection checks)  
**Average detection latency:** 71 seconds  
**Detector CPU overhead:** 0.09%  
**Detector memory overhead:** 117.46 MB  

---

## Dataset

The labelled dataset produced during the experiments is available on request. It consists of five CSV files per phase:

- `cpu_log.csv` — per-container CPU usage at 15-second intervals
- `memory_log.csv` — per-container memory consumption
- `network_log.csv` — per-container TX and RX rates
- `connections_log.csv` — cumulative RX bytes per container
- `restart_log.csv` — container heartbeat observations

Each file contains a `label` column identifying the phase: `baseline`, `Tier1_Stress`, `Tier2_network`, or `Tier3_ha`.

---

## Citation

If you use this work, please cite:

```
Mughogho, T. (2026). Home Assistant: Anomaly Detection in Supervisor Add-ons.
MSc Thesis, Ss. Cyril and Methodius University, Skopje, North Macedonia.
```

---

## Licence

This repository is made available for research and educational purposes. The attack simulation scripts in `attacks/` are included solely for reproducibility of the thesis experiments and should not be used maliciously.
