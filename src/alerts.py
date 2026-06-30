import json
import os
from datetime import datetime, timedelta
from playbook import get_response, format_response

ALERT_LOG_PATH    = "/share/anomaly_detector/alerts/alert_log.json"
ALERT_TEXT_PATH   = "/share/anomaly_detector/alerts/latest_alerts.txt"
ALERT_NOTIFY_PATH = "/share/anomaly_detector/alerts/notify.json"

COOLDOWN_MINUTES = {
    "LOW":      5,
    "MEDIUM":   10,
    "HIGH":     5,
    "CRITICAL": 2,
}

_cooldown_tracker = {}
_alert_history    = []


def _should_alert(container, anomaly_type, risk_level):
    key = (container, anomaly_type)
    now = datetime.now()
    if key in _cooldown_tracker:
        cooldown_mins = COOLDOWN_MINUTES.get(risk_level, 10)
        if now - _cooldown_tracker[key] < timedelta(minutes=cooldown_mins):
            return False
    _cooldown_tracker[key] = now
    return True


def send_alert(container, anomaly_type, metric_value=None, threshold=None, extra=None):
    entry = get_response(anomaly_type)
    risk  = entry["risk"]
    if not _should_alert(container, anomaly_type, risk):
        return False

    timestamp = datetime.now().isoformat()
    alert = {
        "timestamp":    timestamp,
        "container":    container,
        "anomaly_type": anomaly_type,
        "risk":         risk,
        "tier":         entry["tier"],
        "metric_value": round(metric_value, 4) if metric_value else None,
        "threshold":    round(threshold, 4)    if threshold    else None,
        "extra":        extra or {},
        "description":  entry["description"],
        "actions":      entry["actions"],
    }
    _alert_history.append(alert)

    # Write to JSON log
    os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
    existing = []
    if os.path.exists(ALERT_LOG_PATH):
        try:
            with open(ALERT_LOG_PATH, "r") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(alert)
    with open(ALERT_LOG_PATH, "w") as f:
        json.dump(existing, f, indent=2)

    # Write human readable alert
    formatted = format_response(anomaly_type, container, metric_value, threshold)
    with open(ALERT_TEXT_PATH, "a") as f:
        f.write(f"\n[{timestamp}]\n{formatted}\n")

    # Write HA notification file
    notify = {
        "timestamp": timestamp,
        "title":     f"WARNING {risk} Risk - {container}",
        "message":   entry["description"],
        "risk":      risk,
        "anomaly":   anomaly_type,
        "tier":      entry["tier"],
        "action":    entry["actions"][0] if entry["actions"] else "",
    }
    with open(ALERT_NOTIFY_PATH, "w") as f:
        json.dump(notify, f, indent=2)

    print(formatted)
    return True


def get_alert_summary():
    summary = {
        "total_alerts":    len(_alert_history),
        "by_risk":         {},
        "by_anomaly_type": {},
        "by_container":    {},
    }
    for alert in _alert_history:
        r = alert["risk"]
        a = alert["anomaly_type"]
        c = alert["container"]
        summary["by_risk"][r]         = summary["by_risk"].get(r, 0) + 1
        summary["by_anomaly_type"][a] = summary["by_anomaly_type"].get(a, 0) + 1
        summary["by_container"][c]    = summary["by_container"].get(c, 0) + 1
    return summary


def clear_alerts():
    for path in [ALERT_LOG_PATH, ALERT_TEXT_PATH, ALERT_NOTIFY_PATH]:
        if os.path.exists(path):
            os.remove(path)
    _alert_history.clear()
    _cooldown_tracker.clear()
    print("[ALERTS] Alert logs cleared")
