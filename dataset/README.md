# Dataset

## Overview

The dataset used in this research consists of per-container metrics collected
from a live Home Assistant installation at 15-second intervals using the
`collect.py` script in this folder. Because baseline profiles are specific to
each HA installation's hardware and add-ons, the raw CSV files from the thesis
experiments are not included here. Instead, this folder provides the collection
script so researchers can reproduce equivalent data collection on their own setup.

---

## How to Collect Your Own Dataset

### Requirements

- Prometheus running and scraping cAdvisor (see `prometheus/prometheus.yml`)
- Python 3.x with `pandas` and `requests` installed
- Home Assistant running with your normal add-ons active

### Steps

1. Edit `collect.py` and set `PROM_URL` to your Prometheus address
2. Set `LABEL = "baseline"` and `DURATION_SECONDS = 86400` (24 hours)
3. Run `python collect.py` with only your normal add-ons running
4. Wait 24 hours — the script will save CSV files to `research_data/baseline/`
5. For each attack tier, change `LABEL` to `"Tier1_Stress"`, `"Tier2_network"`, 
   or `"Tier3_ha"` and set `DURATION_SECONDS = 14400` (4 hours)
6. Start the corresponding malicious add-on and run `python collect.py`

---

## Dataset Structure

Each phase produces five CSV files:

| File | Columns | Description |
|------|---------|-------------|
| cpu\_log.csv | timestamp, container, cpu\_percent, label | CPU usage rate per container (%) |
| memory\_log.csv | timestamp, container, memory\_mb, label | Memory consumption per container (MB) |
| network\_log.csv | timestamp, container, rx\_bytes\_s, tx\_bytes\_s, label | Network RX and TX rates (bytes/second) |
| restart\_log.csv | timestamp, container, image, label | Container heartbeat observations |
| connections\_log.csv | timestamp, container, interface, rx\_total\_kb, label | Cumulative RX bytes per interface (KB) |

---

## Label Values

| Label | Description |
|-------|-------------|
| `baseline` | Normal operation — only legitimate add-ons running |
| `Tier1_Stress` | Resource abuse attack — stress-ng CPU and memory workers |
| `Tier2_network` | Network attack — curl exfiltration and internal network scan |
| `Tier3_ha` | HA-specific attack — forbidden file access and Supervisor API abuse |

---

## Thesis Dataset Summary

The dataset collected for the thesis experiments contained:

| Phase | Duration | Containers | Observations per container |
|-------|----------|------------|--------------------------|
| Baseline | 24 hours | 7 | 5,760 |
| Tier 1 data collection | 2 hours | 8 | 480 |
| Tier 2 data collection | 2 hours | 8 | 480 |
| Tier 3 data collection | 2 hours | 8 | 480 |

The detection experiments (separate from data collection) ran for 4 hours
per tier, producing 960 observations per container per tier across 7 normal
containers, giving 20,160 total detection checks across all three tiers.

---

## Containers Monitored in Thesis Experiments

Normal add-ons present during all phases:

- `addon_core_samba` — Samba network file share
- `addon_core_ssh` — Terminal and SSH
- `addon_a0d7b954_ssh` — Advanced SSH and Web Terminal
- `addon_core_mosquitto` — Mosquitto MQTT Broker
- `addon_core_configurator` — File Editor
- `addon_core_vlc` — VLC media server
- `hassio_supervisor` — Home Assistant Supervisor (system component)

Malicious add-ons (one per tier, never simultaneous):

- `addon_local_malicious_tier1` — Tier 1 resource abuse
- `addon_local_malicious_tier2` — Tier 2 network attack
- `addon_local_malicious_tier3` — Tier 3 HA-specific attack

---

## Notes

- The `collect.py` script queries Prometheus via HTTP API — Prometheus must
  be running and scraping cAdvisor before starting collection
- The script appends to existing CSV files on each run — start with a fresh
  output directory for each phase
- Timestamps are in local time matching the HA VM system clock
- The `label` column in every file identifies which experimental phase
  produced each row, enabling easy filtering and analysis
