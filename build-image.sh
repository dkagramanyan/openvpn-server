#!/bin/bash
# Build both images locally: openvpn-server:local and openvpn-ui:local
set -euo pipefail
cd "$(dirname "$0")"

start_time=$(date +%s)
printf '\033[1;34mBuilding OpenVPN server image\033[0m\n'
docker build -t openvpn-server:local .
printf '\033[1;34mBuilding OpenVPN UI image\033[0m\n'
docker build -f ui/Dockerfile -t openvpn-ui:local .

elapsed=$(( $(date +%s) - start_time ))
printf '\033[1;34mDone in %02d:%02d\033[0m\n' $((elapsed / 60)) $((elapsed % 60))
