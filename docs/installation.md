# Installation Guide for Home Users

This guide explains how to install and use the anomaly detector in your own 
Home Assistant setup. It is written for non-technical users who want to try 
the system in their home.

> **Important:** This is a research prototype. It is not a fully validated 
> production security product. Treat it as an experimental early-warning 
> system, not a complete security solution.

---

## What You Need

- Home Assistant OS running on any hardware (Raspberry Pi, VM, or dedicated machine)
- A separate computer on the same network to run Prometheus (can be a Windows or Linux machine)
- Basic familiarity with the Home Assistant UI

---

## Step 1 — Install cAdvisor

cAdvisor collects the container metrics the detector needs. Install it by 
opening the Terminal add-on in HA and running:

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

---

## Step 2 — Install Prometheus

On your separate computer, run:

```bash
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

Edit `prometheus.yml` and replace `<HA_VM_IP>` with your HA device's IP address.

---

## Step 3 — Collect Your Baseline

Before the detector can work, it needs to learn what normal looks like for 
your specific add-ons. Run all your normal add-ons for 24 hours without 
starting the detector. This produces the CSV files the detector learns from.

The longer you run the baseline the more accurate the detector will be. 
A minimum of 24 hours is required. Seven days is ideal.

---

## Step 4 — Build Baseline Profiles

Copy the CSV files to `/share/anomaly_detector/baseline/` on your HA device 
via Samba, then run baseline.py to build the statistical profiles.

---

## Step 5 — Install the Detector Add-on

Copy the `src/` folder to `/addons/anomaly_detector/` on your HA device, 
then go to Settings → Add-ons → Add-on Store and install it from Local add-ons.

---

## Step 6 — Start Monitoring

Start the detector add-on. It will immediately begin monitoring all your 
add-ons every 15 seconds. You will see output like:

```
[22:56:00] Iteration 4 | Alerts: 0 | By risk: {}
```

This means everything is normal.

---

## Understanding Alerts

When the detector finds something suspicious you will see a message like:

```
ANOMALY DETECTED
Add-on     : addon_local_suspicious_addon
Alert type : exfiltration
Risk level : HIGH
```

Follow the numbered steps in the alert. Each alert tells you exactly what 
to do in plain language.

**MEDIUM risk** — Stop and investigate the add-on.  
**HIGH risk** — Stop immediately and change your HA password.  
**CRITICAL risk** — Stop immediately, disconnect from internet, rotate all credentials.

---

## After Installing a New Add-on

When you install a new add-on the detector will use conservative global 
fallback thresholds for it until you rebuild the baseline. To get a 
personalised profile for the new add-on:

1. Let it run normally for 24 hours
2. Run baseline.py again to rebuild profiles
3. Restart the detector add-on

---

## Limitations to Understand

- The detector cannot read Supervisor logs due to a sandbox restriction, 
  so some HA-specific attacks may not be detected
- The detector is tuned for the add-ons present during your baseline collection. 
  Adding many new add-ons without rebuilding the baseline may cause false positives
- This is a proof-of-concept research tool, not a commercial security product
