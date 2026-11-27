#!/usr/bin/env bash
# Starts the dev setup: Keycloak, Mailpit, Caddy and two test apps in Docker (compose.yml), and the
# portal from the source code, reloading on every change. Ctrl-C stops the portal; the rest keeps
# running for the next start (stop it with: docker compose -f dev/compose.yml down). See dev/README.md.
set -euo pipefail
dev="$(cd "$(dirname "$0")" && pwd)"
cd "$dev"

mkdir -p .work/caddy
# Caddy needs a Caddyfile to start; the portal replaces this at its start
[ -f .work/caddy/Caddyfile ] || printf 'http://localhost:9 {\n\trespond "starting"\n}\n' > .work/caddy/Caddyfile

echo "Starting Keycloak, Mailpit, Caddy and the test apps (Keycloak takes about a minute the first time)..."
docker compose up -d --wait

cd ../portal
[ -d node_modules ] || npm ci

cat <<MSG

  Lab portal   https://lab.localhost   (a certificate warning per address: see dev/README.md)
  Test apps    https://notes.lab.localhost  https://secret.lab.localhost  https://admintool.lab.localhost
  Emails       http://localhost:8025
  Keycloak     http://localhost:8080   (admin console: admin / admin)

  Test users, password dev-password:
    admin@example.org      lab admin, with a second factor: authenticator app key JJBFGV2ZGNCFARKIKBFTGUCYKA
    member@example.org     invite them on the admin page first
    newcomer@example.org   for a membership request
  Or create an account on the sign-in page (the verification email arrives in Mailpit).

  The portal restarts when you save a file in portal/src. Ctrl-C stops it.

MSG
set -a
# shellcheck disable=SC1091
. "$dev/portal.env"
set +a
exec npm run dev
