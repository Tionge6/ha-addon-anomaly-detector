import pandas as pd
import numpy as np
import os
import json

BASELINE_DIR = "/share/anomaly_detector/baseline"
PROFILE_PATH = "/share/anomaly_detector/baseline_profiles.json"

# Containers to exclude from certain detections
# Supervisor has naturally high network traffic - exclude from network scan
EXCLUDE_NETWORK_SCAN = {
    "hassio_supervisor", "hassio_dns", "hassio_audio", "hassio_cli",
    "hassio_multicast", "hassio_observer", "addon_core_samba",
    "addon_a0d7b954_ssh", "addon_core_ssh", "addon_core_configurator"
}

# Minimum thresholds to prevent zero-value false positives
MIN_THRESHOLDS = {
    "cpu":      {"warning": 5.0,   "critical": 10.0},
    "memory":   {"warning": 50.0,  "critical": 100.0},
    "tx_bytes": {"warning": 100.0, "critical": 500.0},
    "rx_bytes": {"warning": 100.0, "critical": 500.0},
    "rx_growth":{"warning": 50.0,  "critical": 200.0},
}

# Minimum percentage above baseline mean before alerting
MIN_PERCENT_ABOVE_MEAN = {
    "cpu":      {"warning": 50.0,  "critical": 100.0},
    "memory":   {"warning": 20.0,  "critical": 50.0},
    "tx_bytes": {"warning": 50.0,  "critical": 100.0},
    "rx_bytes": {"warning": 50.0,  "critical": 100.0},
    "rx_growth":{"warning": 50.0,  "critical": 100.0},
}

def compute_stats(values):
    arr = np.array(values, dtype=float)
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return {"mean": 0, "std": 0, "min": 0, "max": 0,
                "warning_threshold": 0, "critical_threshold": 0}
    mean = float(np.mean(arr))
    std  = float(np.std(arr))
    return {
        "mean": round(mean, 4),
        "std":  round(std, 4),
        "min":  round(float(np.min(arr)), 4),
        "max":  round(float(np.max(arr)), 4),
        "warning_threshold":  round(mean + 3 * std, 4),
        "critical_threshold": round(mean + 4 * std, 4),
    }

def build_profiles():
    profiles = {}

    cpu_path = os.path.join(BASELINE_DIR, "cpu_log.csv")
    if os.path.exists(cpu_path):
        print("[BASELINE] Building CPU profiles...")
        cpu_df = pd.read_csv(cpu_path)
        for container, group in cpu_df.groupby("container"):
            if container not in profiles:
                profiles[container] = {}
            profiles[container]["cpu"] = compute_stats(group["cpu_percent"].tolist())

    mem_path = os.path.join(BASELINE_DIR, "memory_log.csv")
    if os.path.exists(mem_path):
        print("[BASELINE] Building Memory profiles...")
        mem_df = pd.read_csv(mem_path)
        for container, group in mem_df.groupby("container"):
            if container not in profiles:
                profiles[container] = {}
            profiles[container]["memory"] = compute_stats(group["memory_mb"].tolist())

    net_path = os.path.join(BASELINE_DIR, "network_log.csv")
    if os.path.exists(net_path):
        print("[BASELINE] Building Network profiles...")
        net_df = pd.read_csv(net_path)
        for container, group in net_df.groupby("container"):
            if container not in profiles:
                profiles[container] = {}
            profiles[container]["tx_bytes"] = compute_stats(group["tx_bytes_s"].tolist())
            profiles[container]["rx_bytes"] = compute_stats(group["rx_bytes_s"].tolist())
            profiles[container]["exclude_network_scan"] = (
                container in EXCLUDE_NETWORK_SCAN
            )

    restart_path = os.path.join(BASELINE_DIR, "restart_log.csv")
    if os.path.exists(restart_path):
        print("[BASELINE] Building Restart profiles...")
        restart_df = pd.read_csv(restart_path)
        for container, group in restart_df.groupby("container"):
            if container not in profiles:
                profiles[container] = {}
            profiles[container]["restart"] = {
                "baseline_count":    len(group),
                "expected_per_hour": 240,
                "max_gap_warning":   3,
                "max_gap_critical":  7,
            }

    conn_path = os.path.join(BASELINE_DIR, "connections_log.csv")
    if os.path.exists(conn_path):
        print("[BASELINE] Building Connections profiles...")
        conn_df = pd.read_csv(conn_path)
        for container, group in conn_df.groupby("container"):
            if container not in profiles:
                profiles[container] = {}
            group = group.sort_values("timestamp")
            rx_vals = group["rx_total_kb"].tolist()
            growth_rates = [
                rx_vals[i] - rx_vals[i-1]
                for i in range(1, len(rx_vals))
                if rx_vals[i] >= rx_vals[i-1]
            ]
            profiles[container]["rx_growth"] = compute_stats(growth_rates)

    with open(PROFILE_PATH, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"[BASELINE] Profiles saved. Containers: {list(profiles.keys())}")
    return profiles

def load_profiles():
    if os.path.exists(PROFILE_PATH):
        print(f"[BASELINE] Loading profiles from {PROFILE_PATH}")
        with open(PROFILE_PATH, "r") as f:
            return json.load(f)
    else:
        print("[BASELINE] No saved profiles found - building from CSV...")
        return build_profiles()

def get_threshold(profiles, container, metric, level="warning"):
    GLOBAL_FALLBACK = {
        "cpu":      {"warning": 50.0,  "critical": 100.0},
        "memory":   {"warning": 300.0, "critical": 600.0},
        "tx_bytes": {"warning": 600.0, "critical": 1000.0},
        "rx_bytes": {"warning": 600.0, "critical": 1000.0},
        "rx_growth":{"warning": 500.0, "critical": 1000.0},
    }

    if container in profiles and metric in profiles[container]:
        key = f"{level}_threshold"
        computed = profiles[container][metric].get(
            key, GLOBAL_FALLBACK.get(metric, {}).get(level, 999999)
        )
        min_val = MIN_THRESHOLDS.get(metric, {}).get(level, 0)
        mean_val = profiles[container][metric].get("mean", 0)
        min_pct  = MIN_PERCENT_ABOVE_MEAN.get(metric, {}).get(level, 20.0)
        pct_threshold = mean_val * (1 + min_pct / 100.0)
        return max(computed, min_val, pct_threshold)

    print(f"[BASELINE] No profile for {container}/{metric} - using fallback")
    return GLOBAL_FALLBACK.get(metric, {}).get(level, 999999)

def is_excluded_from_network_scan(profiles, container):
    if container in profiles:
        return profiles[container].get("exclude_network_scan", False)
    return container in EXCLUDE_NETWORK_SCAN

if __name__ == "__main__":
    print("Building baseline profiles...")
    profiles = build_profiles()
    print("\nSample - addon_core_samba CPU:")
    if "addon_core_samba" in profiles:
        print(json.dumps(profiles["addon_core_samba"].get("cpu", {}), indent=2))
