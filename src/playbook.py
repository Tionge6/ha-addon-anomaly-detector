PLAYBOOK = {
    "cpu_spike": {
        "risk": "MEDIUM",
        "tier": "Tier 1 - Resource Abuse",
        "description": "An add-on is consuming unusually high CPU resources.",
        "likely_attack": "Resource exhaustion or cryptocurrency mining.",
        "actions": [
            "Go to Settings -> Add-ons and identify the add-on in the alert.",
            "Press STOP to immediately halt the add-on.",
            "Check when you installed it and whether it came from a trusted source.",
            "If unrecognised, uninstall it completely.",
            "Restart Home Assistant via Settings -> System -> Restart."
        ]
    },
    "memory_spike": {
        "risk": "MEDIUM",
        "tier": "Tier 1 - Resource Abuse",
        "description": "An add-on is consuming abnormally large amounts of memory.",
        "likely_attack": "Memory exhaustion attack or severe memory leak.",
        "actions": [
            "Go to Settings -> Add-ons and identify the add-on in the alert.",
            "Press STOP immediately.",
            "Restart Home Assistant via Settings -> System -> Restart.",
            "If the problem returns, uninstall the add-on.",
            "Check the add-on reviews and recent updates."
        ]
    },
    "exfiltration": {
        "risk": "HIGH",
        "tier": "Tier 2 - Network Attack",
        "description": "An add-on is sending unusually large amounts of data externally.",
        "likely_attack": "Data exfiltration - personal data may be stolen.",
        "actions": [
            "IMMEDIATELY stop the add-on via Settings -> Add-ons -> STOP.",
            "Change your Home Assistant password via Settings -> People.",
            "Revoke all long-lived access tokens on your profile page.",
            "Check your router logs for suspicious external connections.",
            "Uninstall the add-on completely.",
            "Change passwords for any smart devices connected to HA."
        ]
    },
    "network_scan": {
        "risk": "HIGH",
        "tier": "Tier 2 - Network Attack",
        "description": "An add-on is scanning all devices on your home network.",
        "likely_attack": "Internal network reconnaissance before a wider attack.",
        "actions": [
            "IMMEDIATELY stop the add-on via Settings -> Add-ons -> STOP.",
            "Change your Wi-Fi password.",
            "Check all smart devices for unusual behaviour.",
            "Uninstall the add-on completely.",
            "Run a security scan from your router admin panel."
        ]
    },
    "forbidden_access": {
        "risk": "CRITICAL",
        "tier": "Tier 3 - HA Specific Attack",
        "description": "An add-on attempted to access sensitive HA files it has no permission to access.",
        "likely_attack": "Credential theft - attempting to steal passwords and auth tokens.",
        "actions": [
            "IMMEDIATELY stop the add-on via Settings -> Add-ons -> STOP.",
            "Change your Home Assistant password NOW.",
            "Revoke ALL long-lived access tokens on your profile page.",
            "Rotate every password and API key in your secrets.yaml file.",
            "Uninstall the add-on completely.",
            "Consider a full reinstall if you suspect deep compromise.",
            "Report to HA security team at security@home-assistant.io"
        ]
    },
    "supervisor_abuse": {
        "risk": "CRITICAL",
        "tier": "Tier 3 - HA Specific Attack",
        "description": "An add-on called Supervisor APIs beyond its declared permissions.",
        "likely_attack": "Privilege escalation - attempting to gain admin control of HA.",
        "actions": [
            "IMMEDIATELY stop the add-on via Settings -> Add-ons -> STOP.",
            "Check Settings -> System -> Logs for unusual system changes.",
            "Verify all other add-ons are running normally.",
            "Uninstall the suspicious add-on completely.",
            "Restore from your most recent clean backup if needed.",
            "Report to HA security team at security@home-assistant.io"
        ]
    },
    "restart_loop": {
        "risk": "MEDIUM",
        "tier": "Tier 3 - HA Specific Attack",
        "description": "An add-on is repeatedly disappearing and restarting unusually.",
        "likely_attack": "Supervisor terminating the add-on after permission violations.",
        "actions": [
            "Go to Settings -> Add-ons and check the Logs tab for the add-on.",
            "Look for repeated permission denied errors.",
            "Stop the add-on via Settings -> Add-ons -> STOP.",
            "If source is unknown or untrusted, uninstall immediately.",
            "Contact the developer if you believe it is a legitimate bug."
        ]
    },
    "combined_attack": {
        "risk": "CRITICAL",
        "tier": "Multiple Tiers - Combined Attack",
        "description": "Multiple simultaneous anomalies detected from the same add-on.",
        "likely_attack": "Sophisticated multi-vector attack. Immediate action required.",
        "actions": [
            "IMMEDIATELY stop the add-on via Settings -> Add-ons -> STOP.",
            "Disconnect Home Assistant from the internet at your router.",
            "Change ALL passwords - HA account, Wi-Fi, and secrets.yaml entries.",
            "Revoke ALL authentication tokens via your profile page.",
            "Restore from your most recent clean backup.",
            "Report to HA security team at security@home-assistant.io"
        ]
    }
}


def get_response(anomaly_type):
    if anomaly_type in PLAYBOOK:
        return PLAYBOOK[anomaly_type]
    return {
        "risk": "MEDIUM",
        "tier": "Unknown",
        "description": f"Unusual behaviour detected: {anomaly_type}",
        "likely_attack": "Unknown pattern - manual investigation recommended.",
        "actions": [
            "Go to Settings -> Add-ons and review the add-on in the alert.",
            "Check the add-on logs for unusual activity.",
            "If in doubt, stop the add-on and investigate before restarting."
        ]
    }


def format_response(anomaly_type, container, metric_value=None, threshold=None):
    entry = get_response(anomaly_type)
    metric_context = ""
    if metric_value is not None and threshold is not None:
        metric_context = f"\n  Detected value : {metric_value:.4f}\n  Alert threshold: {threshold:.4f}"
    lines = [
        "=" * 60,
        "  ANOMALY DETECTED",
        "=" * 60,
        f"  Add-on     : {container}",
        f"  Alert type : {anomaly_type}",
        f"  Risk level : {entry['risk']}",
        f"  Category   : {entry['tier']}",
        metric_context,
        "",
        "WHAT IS HAPPENING:",
        f"  {entry['description']}",
        "",
        "LIKELY ATTACK:",
        f"  {entry['likely_attack']}",
        "",
        "WHAT YOU SHOULD DO:",
    ]
    for i, action in enumerate(entry["actions"], 1):
        lines.append(f"  {i}. {action}")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_response("exfiltration", "addon_local_malicious_tier2", 555.13, 10.5))
