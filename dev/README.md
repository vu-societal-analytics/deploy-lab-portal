# The dev setup

The lab portal on your own computer, to try a change before a release: Keycloak with test users,
Mailpit for the emails, Caddy, and two small test apps run in Docker; the portal runs from the source
code and restarts whenever you save a file in `portal/src`. Works on Linux and macOS (with Docker
Desktop); needs Node 24 and ports 80, 443, 1025, 3000, 8025 and 8080 free on 127.0.0.1.

```bash
./dev/start.sh
```

Then open **https://lab.localhost**. Browsers send `lab.localhost` and every `*.lab.localhost` to your
own computer by themselves (Chrome, Firefox, Edge; not Safari), so there is nothing to set up for the
addresses. Ctrl-C stops the portal; the rest keeps running for the next start. To stop and remove it all:

```bash
docker compose -f dev/compose.yml down -v
```

## Signing in

Every test user has the password `dev-password`.

| User | What for |
| --- | --- |
| `admin@example.org` | Lab admin (in `config/admins.yml`), with a second factor: add the key `JJBFGV2ZGNCFARKIKBFTGUCYKA` to an authenticator app (time-based, 6 digits, 30 seconds) |
| `member@example.org` | Invite this address on the admin page first; then they are a member at their first sign-in |
| `newcomer@example.org` | Not a member: for trying a membership request |

You can also create an account on the sign-in page: the verification email arrives in Mailpit, at
**http://localhost:8025**, as do the portal's own emails (invitations, notifications to the admins).
Keycloak's admin console is at **http://localhost:8080** (`admin` / `admin`).

## What is where

| File | What |
| --- | --- |
| `compose.yml` | Keycloak, Mailpit, Caddy and the test apps |
| `realm.json` | The Keycloak realm `dev`: the minimal realm of the end-to-end test, with the users above, email verification through Mailpit, and the session times of our idp realm |
| `config/services.yml` | The test apps behind the portal (`notes`, `secret` with a second factor, `admintool` for admins). Edit it while the portal runs: the change reaches Caddy within seconds |
| `config/admins.yml` | The admin |
| `portal.env` | The portal's settings |
| `.work/` | The portal's database and the generated Caddyfile (not in git) |

## The certificate warning

Caddy makes its own certificates for `*.localhost`, so the browser warns once per address. To stop
that, trust Caddy's local root certificate:

```bash
docker compose -f dev/compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

and add `caddy-root.crt` to the trusted certificates of your system (macOS: open it in Keychain Access,
and set it to **Always Trust**) or of your browser (Firefox: Settings, Certificates, Import). Remove it
again when you no longer need it.

## Before a release

Besides trying a change here, run the unit tests (`cd portal && npm test`) and, on Linux, the
end-to-end test (`test/e2e/run.sh`): it builds the portal's image and goes through everything in a
browser.
