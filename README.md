# deploy-lab-portal

The front door of the lab server: **Caddy** (HTTPS for `lab.<domain>` and every service under it) and
the **portal**, a small Hono app that

- signs people in with the lab's OIDC provider (the same Keycloak realm as AmCAT and AnnoTinder, following
  the lab's Authentication standard),
- decides for Caddy who may use which service (forward auth),
- lists the services a person can use,
- handles lab membership: requests (the admins get an email, and approve them on the admin page) and
  invitations by email address.

Background and the full server setup: the lab's infrastructure documentation
(Servers → Lab server, Installation guides → Lab server).

## How it fits together

```
browser ──► Caddy :443 ──► lab.<domain>            ──► portal (login, overview, membership, admin)
                      └──► <service>.lab.<domain>  ──► forward auth: portal /auth ──► allowed? ──► the service
```

For every request to a service, Caddy asks the portal. The portal answers: allowed (and Caddy passes
the person's account ID and email address to the service), sign in first, or a page that explains why
not (not a member yet: request membership; a second factor needed: how to add one; admins only).

**Settings are files on the server; everything the app changes is in its database.**

| where                   | what                                                                     | changed by |
|-------------------------|--------------------------------------------------------------------------|------------|
| `config/services.yml`   | the services: address, upstream, who may use them, second factor or not  | admins, over SSH |
| `config/admins.yml`     | the lab admins, by account ID                                            | admins, over SSH |
| `.env`                  | the provider, the client secret, email, session times                    | admins, over SSH |
| `data/portal.db`        | users, members, invitations, requests, sessions, the log (SQLite)        | the portal |

So the admin page can only change who is a member: someone who takes over an admin's browser can't open
a service to everyone or make themselves admin. The portal turns `services.yml` into `caddy/Caddyfile`,
and Caddy reloads it. A daily copy of the database (without sessions) goes to `backups/`.

### People: by account, not by email address

The portal knows people by the provider's issuer and account ID (`iss` and `sub`), like AmCAT and
AnnoTinder. The email address is stored too (updated at every sign-in), for email and to show who is who.

- **Everyone who signs in** gets a row in `users`. Not a member yet: they can request membership,
  once their email address is verified by the provider.
- **Invitations:** an admin invites an email address on the admin page (the person gets an email). The
  first sign-in with that address, verified by the provider, makes them a member; the invitation is then
  used up. Someone who already signed in with that verified address becomes a member at once.
- **Admins** are listed in `admins.yml` by account ID. Everyone sees their account ID at the bottom of
  the portal once signed in.
- **Services receive** `X-Auth-Request-User` (the account ID: use this to recognize people) and
  `X-Auth-Request-Email`. Caddy removes both from incoming requests, so they can't be forged.

### Access rules

| `access`  | who                                                         |
|-----------|-------------------------------------------------------------|
| `members` | lab members and admins                                      |
| `admins`  | lab admins                                                  |
| `public`  | anyone (no lab login: the service has its own, or is public) |

Every `members` or `admins` service sets `mfa`: `required` (only with a login with a second factor: the
`amr` claim contains `mfa`) or `optional`. The portal asks everyone without a second factor to add one.
Admin changes always need a login with a second factor: at most an hour ago (`AUTH_STEP_UP_MAX_AGE`),
and at most 15 minutes since that login or the last admin change (`AUTH_STEP_UP_IDLE`; each change
renews it, like GitHub's "sudo mode"). Otherwise the admin page asks to sign in again.

`api_bypass` lists paths where requests **with an `Authorization` header** skip the lab login, so
scripts can use the service's own API keys. Only for services that check those keys themselves.

### Sessions

One sign-in for the whole lab zone (a cookie on `lab.<domain>`, holding a random token; the database
only has its hash). The portal keeps its own sessions, independent of Keycloak's (as the lab's
Authentication standard prescribes):

- **Limits:** 30 minutes without use, 24 hours in total (`AUTH_SESSION_IDLE`, `AUTH_SESSION_MAX`):
  OWASP's idle and absolute timeouts, within NIST SP 800-63B-4's limits for logins with a second factor.
- **Per app:** an app can have its own limits in `services.yml` (`session_idle`, `session_max`), e.g.
  a notebook server that computes for hours while the user does nothing. The session then counts for
  that app under its limits; the portal and other apps keep the defaults. Any request counts as activity.
- **Sign-out:** in the portal, which also ends the Keycloak session (so the next sign-in, to any app,
  asks for the password again). A sign-out in another app, or at Keycloak, doesn't end the portal's
  session: apps don't depend on each other's sign-out.
- **Locking someone out:** removing a member ends their portal sessions at once. In an emergency, also
  disable them in Keycloak, so they can't sign in to any app again.

## Setup

On the lab server, in `/opt/lab-portal`, as the account that owns the apps (`sal` on our servers):

1. **Keycloak**: in the realm (the one AmCAT and AnnoTinder use), create the client `lab-portal`:
   - Client authentication **on** (confidential), Standard flow only, PKCE method **S256**
   - Valid redirect URI: `https://<LAB_DOMAIN>/callback`
   - Valid post logout redirect URI: `https://<LAB_DOMAIN>/signed-out`
   - Front channel logout **off**
   - Copy the client secret (Credentials tab).

   The portal needs the claims `email`, `email_verified` and `amr` (with `mfa` after a second factor).
2. **Download and fill in the settings** (the version: see the repository's tags):
   ```bash
   mkdir -p /opt/lab-portal/config /opt/lab-portal/caddy && cd /opt/lab-portal
   V=v0.1.0; R=https://raw.githubusercontent.com/vu-societal-analytics/deploy-lab-portal/$V
   curl -fsSLO $R/compose.yml
   curl -fsSL -o .env $R/.env.example && chmod 600 .env       # fill in: LAB_DOMAIN, OIDC_*, SMTP_*
   curl -fsSL -o config/services.yml $R/config/services.example.yml
   curl -fsSL -o config/admins.yml $R/config/admins.example.yml
   mkdir -p data backups && sudo chown 1000:1000 data backups caddy
   ```
   The portal runs as user 1000 in its container: it writes `data/`, `backups/` and `caddy/Caddyfile`.
3. **Start** (ports 80 and 443 must be free: stop any other web server first):
   ```bash
   sudo docker compose pull && sudo docker compose up -d
   sudo docker compose logs -f
   ```
4. **DNS**: `lab.<domain>` and `*.lab.<domain>` point to the server. Caddy gets a certificate per
   address from Let's Encrypt.
5. **The first admin**: sign in on `https://<LAB_DOMAIN>`, copy the account ID from the bottom of the
   page into `config/admins.yml` (replacing the example), and reload the page: the **Admin** link appears.

## Daily use

- **Members**: on `https://<LAB_DOMAIN>/admin`: approve or reject requests, invite people by email
  address (one, or a pasted list at once, with or without invitation emails), remove members.
- **Add or change a service**: edit `config/services.yml`. The portal checks the file; when it is
  invalid it keeps the previous settings and logs why (`docker compose logs portal`).
- **An old address that moved** (e.g. under `lab.`): add it under `redirects:` in `services.yml`.
- **Admins**: edit `config/admins.yml`.
- **Update**: download the `compose.yml` of the new version (it names its own image), then
  `sudo docker compose pull && sudo docker compose up -d`. If the portal then refuses to start with
  "has database version", the database format changed: see the release notes of that version.

## Settings (.env)

See `.env.example`. Besides those, for tests only: `AUTH_INSECURE_DISABLE_2FA`,
`AUTH_INSECURE_DISABLE_EMAIL_VERIFICATION` (the lab's Authentication standard), and
`TEST_ALLOW_HTTP_ISSUER`, `TEST_LOCAL_CERTS`.

## Development and tests

**Releases:**

1. Set the new version in `compose.yml` (the `image:` line, e.g. `lab-portal:0.2.0`), commit and push to `main`.
2. On GitHub: **Releases → Draft a new release**, tag `v0.2.0` (with a `v`; created on `main`), publish.
3. GitHub Actions (`.github/workflows/image.yml`) runs the tests and publishes
   `ghcr.io/vu-societal-analytics/lab-portal:0.2.0` (without the `v`); if the tests fail, nothing is published.
4. On the server: download the `compose.yml` of the new version, then `sudo docker compose pull && sudo docker compose up -d`.

**Trying a change on your own computer:** `./dev/start.sh` starts Keycloak with test users, a mail
catcher, Caddy and two test apps in Docker, and the portal from the source code, restarting on every
change. Then open https://lab.localhost. Details and the test users: [dev/README.md](dev/README.md).

```bash
cd portal
npm ci
npm test            # unit tests: access rules, settings, Caddyfile, users and members, email, backups
```

**End-to-end test** (`test/e2e`): Keycloak with a minimal realm (`realm.json`: only what the
Authentication standard asks of a provider, not our production realm), a mail catcher, the portal's
Docker image and Caddy, and a browser that goes through login, requests, invitations, access per
service, 2FA, sign-out, independence from the Keycloak session, the API bypass and settings reloads. Takes about 3 minutes;
Linux only (it uses Docker's host network), and ports 80, 443, 1025, 3000, 8025 and 8080 on this machine (not on the server).

```bash
cd test/e2e
npm install && npx playwright install chromium   # once
./run.sh
```

Files in `portal/src`:

| file          | what                                                                     |
|---------------|--------------------------------------------------------------------------|
| `server.ts`   | start: settings, Caddyfile, database, OIDC, timers                       |
| `app.tsx`     | the routes: login, callback, forward auth, sign-out, membership, admin   |
| `authz.ts`    | the access decision per service, and safe return addresses               |
| `oidc.ts`     | OIDC login (PKCE, state, nonce), sign-out                                |
| `settings.ts` | reads and validates services.yml and admins.yml, reloads on change       |
| `caddy.ts`    | the Caddyfile from services.yml                                          |
| `db.ts`       | the SQLite database and its daily copy                                   |
| `mail.ts`     | notifications to admins (throttled, daily reminder), invitations, welcome |
| `views.tsx`   | the pages                                                                |
| `config.ts`   | the settings from the environment                                        |
