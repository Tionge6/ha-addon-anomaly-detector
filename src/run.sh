#!/bin/bash
echo "============================================"
echo "  HA Addon Anomaly Detector Starting"
echo "============================================"
mkdir -p /share/anomaly_detector/baseline
mkdir -p /share/anomaly_detector/alerts
if [ ! -f "/share/anomaly_detector/baseline/cpu_log.csv" ]; then
    echo "[WARN] Baseline CSV files not found"
    echo "[WARN] Using fallback global thresholds"
fi
echo "[INFO] Starting detection loop..."
cd /app && python detector.py
