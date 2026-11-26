#!/usr/bin/env bash
# The end-to-end test: starts Keycloak, a mail catcher, the portal and Caddy (compose.yml), runs the
# browser test (e2e.cjs), and stops everything. Needs Docker, Node and Playwright with Chromium
# (npm install && npx playwright install chromium, in this folder).
#   ./run.sh            build the portal image and run the test
#   KEEP=1 ./run.sh     leave everything running afterwards (stop with: docker compose down)
set -euo pipefail
cd "$(dirname "$0")"

# A fresh working copy of the settings and empty data, writable by the portal (user 1000)
rm -rf .work
mkdir -p .work/caddy .work/data .work/backups
cp -r config .work/config
chmod -R a+rwX .work

build=--build
[ -z "${NO_BUILD:-}" ] || build=--no-build   # NO_BUILD=1: use the image built before
docker compose up -d "$build" --wait
status=0
node e2e.cjs || status=$?
if [ "$status" -ne 0 ]; then docker compose logs portal | tail -40; fi
[ -n "${KEEP:-}" ] || docker compose down -v
exit "$status"
