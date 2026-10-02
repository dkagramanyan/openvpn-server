#!/bin/bash
# End-to-end test of the whole service: the server, the web UI and real OpenVPN
# clients, all inside one Docker-in-Docker container. Its networks, tun devices
# and firewall rules live in that container's namespace, so the machine that
# runs the test is not touched.
#
#   tests/e2e/run.sh            build the images, run the test, remove the container
#   E2E_KEEP=1 tests/e2e/run.sh keep it afterwards (UI on http://<container IP>:8080,
#                               admin / e2e-password); remove with: docker rm -f -v ovpn-e2e
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NAME=${E2E_NAME:-ovpn-e2e}

docker build -q -t openvpn-server:e2e "$ROOT" >/dev/null
docker build -q -t openvpn-ui:e2e -f "$ROOT/ui/Dockerfile" "$ROOT" >/dev/null

docker rm -f -v "$NAME" >/dev/null 2>&1 || true
docker run -d --privileged --name "$NAME" -e DOCKER_TLS_CERTDIR= docker:dind >/dev/null
[[ -n ${E2E_KEEP:-} ]] || trap 'docker rm -f -v "$NAME" >/dev/null' EXIT
for _ in $(seq 60); do docker exec "$NAME" docker info >/dev/null 2>&1 && break; sleep 1; done

docker save openvpn-server:e2e openvpn-ui:e2e | docker exec -i "$NAME" docker load >/dev/null
# The repository as git sees it: none of a real deployment's keys, database or .env.
git -C "$ROOT" ls-files -co --exclude-standard -z | tar -C "$ROOT" --null -T - -cf - \
    | docker exec -i "$NAME" sh -c 'mkdir -p /srv/openvpn && tar -C /srv/openvpn -xf -'

docker exec "$NAME" sh /srv/openvpn/tests/e2e/inside.sh
