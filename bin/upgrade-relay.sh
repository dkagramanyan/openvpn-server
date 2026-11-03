#!/bin/bash
# Upgrade application/relay services and import previous state; keep OpenVPN running.
set -euo pipefail
cd "$(dirname "$0")/.."
DOCKER=(docker)
if [[ ${1:-} == --sudo-docker ]]; then DOCKER=(sudo docker); shift; fi
[[ $# == 0 ]] || { echo "Usage: bin/upgrade-relay.sh [--sudo-docker]" >&2; exit 2; }
python3 bin/setup-env.py
"${DOCKER[@]}" compose config --quiet
# Build before the old UI is stopped. No database is removed or recreated here.
"${DOCKER[@]}" compose build openvpn-ui apple-relay
"${DOCKER[@]}" compose up -d --wait --wait-timeout 120 postgres
# Keep the old containers available until the import has committed.
mapfile -t previous < <("${DOCKER[@]}" compose ps -q openvpn-ui relay-policy apple-relay)
"${DOCKER[@]}" compose stop openvpn-ui relay-policy apple-relay
# The import checks row counts and commits as a single PostgreSQL transaction.
if ! "${DOCKER[@]}" compose run --rm --no-deps --entrypoint python openvpn-ui -m app.migrate_db import; then
    echo 'Migration failed. Restarting the previous containers; the SQLite source was not changed.' >&2
    if ((${#previous[@]})); then "${DOCKER[@]}" start "${previous[@]}"; fi
    exit 1
fi
# A fresh installation or restored host may not have a running VPN container.
if [[ -z $("${DOCKER[@]}" compose ps -q openvpn) ]]; then
    "${DOCKER[@]}" compose up -d --no-deps openvpn
fi
"${DOCKER[@]}" compose up -d --no-deps --force-recreate --wait --wait-timeout 120 openvpn-ui
"${DOCKER[@]}" compose up -d --no-deps --force-recreate --wait --wait-timeout 60 relay-policy
"${DOCKER[@]}" compose up -d --no-deps --force-recreate --wait --wait-timeout 60 apple-relay
"${DOCKER[@]}" compose exec -T apple-relay wget -qO- http://127.0.0.1:8446/readyz
printf '\nRelay upgrade completed. Existing profiles remain valid; OpenVPN was not restarted.\n'
