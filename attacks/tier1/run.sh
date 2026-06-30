#!/bin/bash
echo "Starting Tier 1 - Resource abuse attack"
while true; do
    # CPU stress
    stress-ng --cpu 2 --timeout 30s
    # Memory stress
    stress-ng --vm 2 --vm-bytes 256M --timeout 30s
    sleep 5
done
