import requests
import time
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict
from baseline import load_profiles, get_threshold, is_excluded_from_network_scan
from alerts import send_alert, get_alert_summary
import json as _json

try:
    with open('/data/options.json') as _f:
        _opts = _json.load(_f)
    _base_url = "http://127.0.0.1:9090"
    PROM_URL = _base_url.rstrip("/") + "/api/v1/query"
except Exception:
    PROM_URL = "http://127.0.0.1:9090/api/v1/query"

DETECTION_INTERVAL = 15

# Only monitor actual user addons
ADDON_FILTER = 'name=~"addon.*",name!~"addon_local_anomaly_detector.*|addon_builder.*"'

# Combined attack needs 3 different anomaly types
COMBINED_WINDOW    = 5
COMBINED_THRESHOLD = 3

_recent_anomalies     = defaultdict(list)
_restart_tracker      = defaultdict(int)
_restart_window_start = datetime.now()
RESTART_WINDOW_MINS   = 60


def query_prometheus(query):
    try:
        r = requests.get(PROM_URL, params={"query": query}, timeout=10)
        return r.json()["data"]["result"]
    except Exception as e:
        print(f"[DETECTOR] Prometheus query failed: {e}")
        return []


def check_cpu(profiles):
    query   = f'rate(container_cpu_usage_seconds_total{{image!="",{ADDON_FILTER}}}[1m]) * 100'
    results = query_prometheus(query)
    for r in results:
        container = r["metric"].get("name", "unknown")
        val       = float(r["value"][1])
        warn      = get_threshold(profiles, container, "cpu", "warning")
        crit      = get_threshold(profiles, container, "cpu", "critical")
        if val >= crit:
            _register_anomaly(container, "cpu_spike", val, crit)
        elif val >= warn:
            _register_anomaly(container, "cpu_spike", val, warn)


def check_memory(profiles):
    query   = f'container_memory_usage_bytes{{image!="",{ADDON_FILTER}}} / 1048576'
    results = query_prometheus(query)
    for r in results:
        container = r["metric"].get("name", "unknown")
        val       = float(r["value"][1])
        warn      = get_threshold(profiles, container, "memory", "warning")
        crit      = get_threshold(profiles, container, "memory", "critical")
        if val >= crit:
            _register_anomaly(container, "memory_spike", val, crit)
        elif val >= warn:
            _register_anomaly(container, "memory_spike", val, warn)


def check_network(profiles):
    tx_results = query_prometheus(
        f'rate(container_network_transmit_bytes_total{{image!="",{ADDON_FILTER}}}[1m])'
    )
    rx_results = query_prometheus(
        f'rate(container_network_receive_bytes_total{{image!="",{ADDON_FILTER}}}[1m])'
    )
    tx_vals = {r["metric"].get("name", "unknown"): float(r["value"][1]) for r in tx_results}
    rx_vals = {r["metric"].get("name", "unknown"): float(r["value"][1]) for r in rx_results}

    for container in set(list(tx_vals.keys()) + list(rx_vals.keys())):
        if is_excluded_from_network_scan(profiles, container):
            continue

        tx      = tx_vals.get(container, 0)
        rx      = rx_vals.get(container, 0)
        tx_warn = get_threshold(profiles, container, "tx_bytes", "warning")
        tx_crit = get_threshold(profiles, container, "tx_bytes", "critical")
        rx_warn = get_threshold(profiles, container, "rx_bytes", "warning")

        if tx >= tx_warn and rx >= rx_warn:
            _register_anomaly(container, "network_scan", tx, tx_warn,
                              extra={"tx": tx, "rx": rx})
        elif tx >= tx_crit:
            _register_anomaly(container, "exfiltration", tx, tx_crit)
        elif tx >= tx_warn:
            _register_anomaly(container, "exfiltration", tx, tx_warn)


def check_restarts(profiles):
    global _restart_window_start, _restart_tracker
    results = query_prometheus(
        f'container_last_seen{{image!="",{ADDON_FILTER}}}'
    )
    for r in results:
        container = r["metric"].get("name", "unknown")
        _restart_tracker[container] += 1

    now     = datetime.now()
    elapsed = (now - _restart_window_start).total_seconds() / 60
    if elapsed >= RESTART_WINDOW_MINS:
        expected = int(RESTART_WINDOW_MINS * 60 / DETECTION_INTERVAL)
        for container, count in _restart_tracker.items():
            gap      = expected - count
            warn_gap = profiles.get(container, {}).get("restart", {}).get("max_gap_warning",  3)
            crit_gap = profiles.get(container, {}).get("restart", {}).get("max_gap_critical", 7)
            if gap >= crit_gap:
                _register_anomaly(container, "restart_loop", float(gap), float(crit_gap),
                                  extra={"missing": gap, "expected": expected})
            elif gap >= warn_gap:
                _register_anomaly(container, "restart_loop", float(gap), float(warn_gap),
                                  extra={"missing": gap, "expected": expected})
        _restart_tracker.clear()
        _restart_window_start = now


def check_supervisor_logs():
    LOG_PATTERNS = [
        (r"secrets\.yaml",                         "forbidden_access"),
        (r"\.storage/auth",                        "forbidden_access"),
        (r"/ssl/",                                 "forbidden_access"),
        (r"supervisor/addons|supervisor/core/api", "supervisor_abuse"),
        (r"Permission denied.*addon",              "forbidden_access"),
    ]
    ha_cmd = None
    for path in ["/usr/bin/ha", "/usr/local/bin/ha", "/bin/ha"]:
        if os.path.exists(path):
            ha_cmd = path
            break
    if not ha_cmd:
        return  # ha CLI not available inside addon sandbox

    try:
        import subprocess
        result = subprocess.run(
            [ha_cmd, "supervisor", "logs", "--no-color"],
            capture_output=True, text=True, timeout=10
        )
        log_text = result.stdout
        for pattern, anomaly_type in LOG_PATTERNS:
            matches = re.findall(pattern, log_text, re.IGNORECASE)
            if matches:
                container = _extract_container_from_log(log_text, pattern)
                _register_anomaly(
                    container or "unknown_addon",
                    anomaly_type,
                    extra={"match_count": len(matches)}
                )
    except Exception as e:
        print(f"[DETECTOR] Log scan failed: {e}")


def _extract_container_from_log(log_text, pattern):
    try:
        for line in log_text.split("\n"):
            if re.search(pattern, line, re.IGNORECASE):
                match = re.search(r"addon[_/](\w+)", line, re.IGNORECASE)
                if match:
                    return f"addon_{match.group(1)}"
    except Exception:
        pass
    return None


def _register_anomaly(container, anomaly_type, metric_value=None,
                       threshold=None, extra=None):
    now = datetime.now()
    _recent_anomalies[container].append((anomaly_type, now))
    cutoff = now - timedelta(minutes=COMBINED_WINDOW)
    _recent_anomalies[container] = [
        (a, t) for a, t in _recent_anomalies[container] if t > cutoff
    ]
    unique = set(a for a, t in _recent_anomalies[container])
    if len(unique) >= COMBINED_THRESHOLD:
        send_alert(container, "combined_attack",
                   extra={"triggered_by": list(unique)})
    send_alert(container, anomaly_type, metric_value, threshold, extra)


def run_detection_loop():
    print("=" * 60)
    print("  HA Addon Anomaly Detector Starting")
    print(f"  Prometheus : {PROM_URL}")
    print(f"  Interval   : {DETECTION_INTERVAL}s")
    print(f"  Monitoring : user addons only (excluding system containers)")
    print("=" * 60)

    profiles  = load_profiles()
    print(f"[DETECTOR] Loaded profiles for: {list(profiles.keys())}")
    iteration = 0

    while True:
        iteration += 1
        try:
            check_cpu(profiles)
            check_memory(profiles)
            check_network(profiles)
            check_restarts(profiles)
            if iteration % 4 == 0:
                check_supervisor_logs()
            if iteration % 4 == 0:
                summary = get_alert_summary()
                print(
                    f"  [{datetime.now().strftime('%H:%M:%S')}] "
                    f"Iteration {iteration} | "
                    f"Alerts: {summary['total_alerts']} | "
                    f"By risk: {summary['by_risk']}"
                )
        except Exception as e:
            print(f"[DETECTOR] Error in iteration {iteration}: {e}")
        time.sleep(DETECTION_INTERVAL)


if __name__ == "__main__":
    run_detection_loop()
