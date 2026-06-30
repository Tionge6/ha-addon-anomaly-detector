# Reproducibility Guide

This document provides step-by-step instructions for reproducing the 
experimental results reported in the thesis.

---

## Experimental Environment

| Component | Version / Specification |
|-----------|------------------------|
| Host OS | Windows 11 |
| Virtualisation | VirtualBox 7.x, bridged network adapter |
| Home Assistant OS | 16.3 |
| Home Assistant Core | 2025.12.4 |
| Home Assistant Supervisor | 2026.06.2 |
| cAdvisor | gcr.io/cadvisor/cadvisor:latest |
| Prometheus | prom/prometheus:latest |
| Scrape interval | 15 seconds |
| Baseline duration | 24 hours |
| Attack tier duration | 4 hours each |

---

## Normal Add-ons Running During Experiments

The following six add-ons were running throughout all experiments:

1. Samba share (core_samba)
2. Terminal & SSH (core_ssh)
3. Advanced SSH & Web Terminal (a0d7b954_ssh)
4. Mosquitto MQTT Broker (core_mosquitto)
5. File Editor (core_configurator)
6. VLC (core_vlc)

---

## Baseline Collection

The baseline was collected from 2026-04-30 22:06:41 to 2026-05-01 22:06:41 
(24 hours) with all six normal add-ons running and no malicious add-ons present.

---

## Attack Simulation Timeline

| Phase | Start | End | Duration |
|-------|-------|-----|----------|
| Baseline | 2026-04-30 22:06 | 2026-05-01 22:06 | 24 hours |
| Tier 1 data collection | 2026-05-07 13:20 | 2026-05-07 15:21 | 2 hours |
| Tier 2 data collection | 2026-05-08 09:58 | 2026-05-08 11:59 | 2 hours |
| Tier 3 data collection | 2026-05-08 12:09 | 2026-05-08 14:10 | 2 hours |
| Tier 1 detection run | 2026-06-18 17:27 | 2026-06-18 21:27 | 4 hours |
| Tier 2 detection run | 2026-06-18 23:12 | 2026-06-19 03:12 | 4 hours |
| Tier 3 detection run | 2026-06-19 03:40 | 2026-06-19 07:40 | 4 hours |

---

## Expected Detection Results

| Tier | Expected First Alert | Expected Signal | Expected Latency |
|------|---------------------|-----------------|-----------------|
| Tier 1 | Within 60 seconds | cpu\_spike | ~29 seconds |
| Tier 2 | Within 2 minutes | exfiltration | ~107 seconds |
| Tier 3 | Within 2 minutes | exfiltration (partial) | ~78 seconds |

---

## Verifying the Detector is Working

After starting the detector, confirm it shows:

```
[HH:MM:SS] Iteration 4 | Alerts: 0 | By risk: {}
```

for at least 5 consecutive iterations before starting any attack add-on.

After starting a malicious add-on, you should see an ANOMALY DETECTED 
message within the expected latency window for that tier.

---

## PromQL Queries for Verification

Check detector overhead:

```promql
rate(container_cpu_usage_seconds_total{name=~"addon_local_anomaly_detector.*"}[1m]) * 100
container_memory_usage_bytes{name=~"addon_local_anomaly_detector.*"} / 1048576
```

Check malicious add-on CPU during Tier 1:

```promql
rate(container_cpu_usage_seconds_total{name=~"addon_local_malicious_tier1.*"}[1m]) * 100
```

Check malicious add-on TX during Tier 2:

```promql
rate(container_network_transmit_bytes_total{name=~"addon_local_malicious_tier2.*"}[1m])
```
