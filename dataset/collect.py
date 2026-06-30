import requests
import pandas as pd
from datetime import datetime
import time
import os

PROM_URL = "http://localhost:9090/api/v1/query"

# ── Addon filter ──────────────────────────────────────────────────────────────
# Only collect data for actual addons, not system containers
ADDON_FILTER = 'name=~"addon.*|hassio_supervisor"'

# ── Label for this collection session ────────────────────────────────────────
# Change this before each phase:
#   "baseline"        → normal operation (24 hrs minimum, 7 days recommended)
#   "Tier1_Stress"    → stress container running (resource abuse)
#   "Tier2_network"   → malicious addon (network attacks)
#   "Tier3_ha"        → malicious addon (HA specific attacks)
LABEL = "baseline"

# ── Output folder ─────────────────────────────────────────────────────────────
OUTPUT_DIR = f"research_data/{LABEL}"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── How long to collect (seconds) ────────────────────────────────────────────
# baseline:      86400   = 24 hours (minimum)
# attack tiers:  14400   = 4 hours
DURATION_SECONDS = 86400

# ── Interval between collections ─────────────────────────────────────────────
INTERVAL = 15  # seconds


def query_prometheus(query):
    try:
        response = requests.get(PROM_URL, params={"query": query}, timeout=10)
        return response.json()["data"]["result"]
    except Exception as e:
        print(f"  [ERROR] Prometheus query failed: {e}")
        return []


# ── CPU ───────────────────────────────────────────────────────────────────────
def get_cpu_usage():
    query = f'rate(container_cpu_usage_seconds_total{{image!="",{ADDON_FILTER}}}[1m])'
    results = query_prometheus(query)
    data = []
    for r in results:
        container = r["metric"].get("name", "unknown")
        value = round(float(r["value"][1]) * 100, 4)   # convert to %
        timestamp = datetime.fromtimestamp(r["value"][0])
        data.append([timestamp, container, value, LABEL])
    return pd.DataFrame(data, columns=["timestamp", "container", "cpu_percent", "label"])


# ── Memory ────────────────────────────────────────────────────────────────────
def get_memory_usage():
    query = f'container_memory_usage_bytes{{image!="",{ADDON_FILTER}}}'
    results = query_prometheus(query)
    data = []
    for r in results:
        container = r["metric"].get("name", "unknown")
        value = round(float(r["value"][1]) / (1024 * 1024), 2)   # MB
        timestamp = datetime.fromtimestamp(r["value"][0])
        data.append([timestamp, container, value, LABEL])
    return pd.DataFrame(data, columns=["timestamp", "container", "memory_mb", "label"])


# ── Network ───────────────────────────────────────────────────────────────────
def get_network_usage():
    rx_query = f'rate(container_network_receive_bytes_total{{image!="",{ADDON_FILTER}}}[1m])'
    tx_query = f'rate(container_network_transmit_bytes_total{{image!="",{ADDON_FILTER}}}[1m])'
    rx_results = query_prometheus(rx_query)
    tx_results = query_prometheus(tx_query)

    timestamp = datetime.now()
    data = {}

    for r in rx_results:
        name = r["metric"].get("name", "unknown")
        data[name] = {"rx": round(float(r["value"][1]), 4)}

    for r in tx_results:
        name = r["metric"].get("name", "unknown")
        if name in data:
            data[name]["tx"] = round(float(r["value"][1]), 4)
        else:
            data[name] = {"rx": 0, "tx": round(float(r["value"][1]), 4)}

    rows = []
    for name, vals in data.items():
        rows.append([timestamp, name, vals.get("rx", 0), vals.get("tx", 0), LABEL])

    return pd.DataFrame(rows, columns=["timestamp", "container", "rx_bytes_s", "tx_bytes_s", "label"])


# ── Container restarts ────────────────────────────────────────────────────────
def get_restart_count():
    query = f'container_last_seen{{image!="",{ADDON_FILTER}}}'
    results = query_prometheus(query)
    data = []
    for r in results:
        container = r["metric"].get("name", "unknown")
        image = r["metric"].get("image", "unknown")
        timestamp = datetime.fromtimestamp(r["value"][0])
        data.append([timestamp, container, image, LABEL])
    return pd.DataFrame(data, columns=["timestamp", "container", "image", "label"])


# ── Network connections ───────────────────────────────────────────────────────
def get_network_connections():
    rx_query = f'container_network_receive_bytes_total{{image!="",{ADDON_FILTER}}}'
    results = query_prometheus(rx_query)
    data = []
    timestamp = datetime.now()
    for r in results:
        container = r["metric"].get("name", "unknown")
        interface = r["metric"].get("interface", "unknown")
        rx_total = round(float(r["value"][1]) / 1024, 2)  # KB total
        data.append([timestamp, container, interface, rx_total, LABEL])
    return pd.DataFrame(data, columns=["timestamp", "container", "interface", "rx_total_kb", "label"])


# ── Save helper ───────────────────────────────────────────────────────────────
def save(df, filename):
    path = os.path.join(OUTPUT_DIR, filename)
    file_exists = os.path.exists(path)
    df.to_csv(path, mode='a', header=not file_exists, index=False)


# ── Main loop ─────────────────────────────────────────────────────────────────
print("=" * 60)
print(f"  Data Collection Started")
print(f"  Label:     {LABEL}")
print(f"  Output:    {OUTPUT_DIR}/")
print(f"  Duration:  {DURATION_SECONDS // 3600}h {(DURATION_SECONDS % 3600) // 60}m")
print(f"  Interval:  {INTERVAL}s")
print(f"  Started:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

with open("collection_timeline.txt", "a") as f:
    f.write(f"[{LABEL.upper()}] Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

iterations = DURATION_SECONDS // INTERVAL
for i in range(iterations):
    try:
        cpu         = get_cpu_usage()
        mem         = get_memory_usage()
        net         = get_network_usage()
        restarts    = get_restart_count()
        connections = get_network_connections()

        save(cpu,         "cpu_log.csv")
        save(mem,         "memory_log.csv")
        save(net,         "network_log.csv")
        save(restarts,    "restart_log.csv")
        save(connections, "connections_log.csv")

        elapsed = (i + 1) * INTERVAL
        hrs  = elapsed // 3600
        mins = (elapsed % 3600) // 60
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Iteration {i+1}/{iterations} "
              f"({hrs}h {mins}m elapsed) — "
              f"CPU rows: {len(cpu)}, MEM rows: {len(mem)}, NET rows: {len(net)}")

    except Exception as e:
        print(f"  [ERROR] Iteration {i+1} failed: {e}")

    time.sleep(INTERVAL)

with open("collection_timeline.txt", "a") as f:
    f.write(f"[{LABEL.upper()}] End:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

print("=" * 60)
print(f"  Collection complete. Files saved to: {OUTPUT_DIR}/")
print(f"  Files: cpu_log.csv, memory_log.csv, network_log.csv,")
print(f"         restart_log.csv, connections_log.csv")
print("=" * 60)
