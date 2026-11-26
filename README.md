# deploy-lab-portal

The front door of the lab server: **Caddy** (HTTPS for `lab.<domain>` and every service under it) and
the **portal**, a small Hono app that

- signs people in with the lab realm of Keycloak (OIDC, like AmCAT and AnnoTinder),
- decides for Caddy who may use which service (forward auth),
- lists the services a person can use,
- takes membership requests, notifies the lab admins (on the admin page and by email), and lets an
  admin approve them.

Background and the full server setup: the lab's infrastructure documentation
(Servers → Lab server, Installation guides → Lab server).

## How it fits together

```
browser ──► Caddy :443 ──► lab.<domain>            ──► portal (login, overview, membership, admin)
                      └──► <service>.lab.<domain>  ──► forward auth: portal /auth ──► allowed? ──► the service
```

- **Who may use what is configured in files on the server**, not in the app:
  - `config/services.yml`: the services (address, upstream, who may use them, 2FA required or not).
    The portal turns it into `caddy/Caddyfile`; Caddy reloads it on change (within a minute).
  - `config/groups.yml`: the lab admins, and lab members fixed here.
- **The app only stores** members approved in the portal, membership requests, sessions and a log of
  admin actions (`data/portal.db`, SQLite). A daily copy (without sessions) goes to `backups/`.
- **Services get** the headers `X-Auth-Request-Email` and `X-Auth-Request-User`. Caddy removes them from
  incoming requests, so they can't be forged.

### Access rules

| `access`  | who                                                        |
|-----------|------------------------------------------------------------|
| `members` | lab members (approved in the portal or in groups.yml) and admins |
| `admins`  | lab admins                                                 |
| `public`  | anyone (no lab login: the service has its own, or is public) |

`mfa: required` needs a login with a second factor (the `amr` claim contains `mfa`). Lab admins
always need a second factor for admin changes, and a recent one (`AUTH_STEP_UP_MAX_AGE`, 10 min):
the admin page asks them to sign in again otherwise.

`api_bypass` lists paths where requests **with an `Authorization` header** skip the lab login, so
scripts can use the service's own API keys. Only for services that check those keys themselves.

### Sessions

One sign-in for the whole lab zone (a cookie on `lab.<domain>`). A session ends after 12 hours without
use or 7 days in total, on sign-out, or when the person signs out in Keycloak (back-channel logout).
Every 10 minutes it is checked with Keycloak, so a disabled account loses access quickly. Removing a
member in the portal takes effect immediately.

## Setup

On the lab server, as `sal`, in `/opt/lab-portal`:

1. **Keycloak**: in the lab realm, create the client `lab-portal`:
   - Client authentication **on** (confidential), Standard flow only, PKCE method **S256**
   - Valid redirect URI: `https://<LAB_DOMAIN>/callback`
   - Valid post logout redirect URI: `https://<LAB_DOMAIN>/signed-out`
   - Backchannel logout URL: `https://<LAB_DOMAIN>/backchannel-logout`, session required **on**
   - Copy the client secret (Credentials tab).
2. **Settings**:
   ```bash
   cp .env.example .env && chmod 600 .env          # fill in: LAB_DOMAIN, OIDC_*, SMTP_*
   cp config/services.example.yml config/services.yml
   cp config/groups.example.yml config/groups.yml  # at least one admin
   mkdir -p data backups && sudo chown 1000:1000 data backups caddy
   ```
   The portal runs as user 1000 in its container: it writes `data/`, `backups/` and `caddy/Caddyfile`.
3. **Start** (ports 80 and 443 must be free: stop any other web server first):
   ```bash
   docker compose up -d --build
   docker compose logs -f
   ```
4. **DNS**: `lab.<domain>` and `*.lab.<domain>` point to the server. Caddy gets a certificate per
   address from Let's Encrypt.

## Daily use

- **Add or change a service**: edit `config/services.yml`. The portal checks the file; when it is
  invalid it keeps the previous settings and logs why (`docker compose logs portal`).
- **An old address that moved** (e.g. under `lab.`): add it under `redirects:` in `services.yml`.
- **Admins and fixed members**: edit `config/groups.yml`.
- **Members**: on `https://<LAB_DOMAIN>/admin` (approve requests, add or remove members).
- **Update**: `git pull && docker compose up -d --build`.

## Settings (.env)

See `.env.example`. Besides those, for tests only: `AUTH_INSECURE_DISABLE_2FA`,
`AUTH_INSECURE_DISABLE_EMAIL_VERIFICATION` (the lab's Authentication standard), and
`TEST_ALLOW_HTTP_ISSUER`, `TEST_LOCAL_CERTS`.

## Development

```bash
cd portal
npm ci
npm test            # unit tests: access rules, settings validation, Caddyfile, email, backups
npm run dev         # needs the settings of .env in the environment, and a reachable Keycloak
```

Files in `portal/src`:

| file          | what                                                                 |
|---------------|----------------------------------------------------------------------|
| `server.ts`   | start: settings, Caddyfile, database, OIDC, timers                   |
| `app.tsx`     | the routes: login, callback, forward auth, sign-out, membership, admin |
| `authz.ts`    | the access decision per service, and safe return addresses           |
| `oidc.ts`     | OIDC login (PKCE), refresh, sign-out, back-channel logout tokens      |
| `settings.ts` | reads and validates services.yml and groups.yml, reloads on change   |
| `caddy.ts`    | the Caddyfile from services.yml                                      |
| `db.ts`       | the SQLite database and its daily copy                               |
| `mail.ts`     | notifications to admins (throttled, daily reminder), welcome email   |
| `views.tsx`   | the pages                                                            |
| `config.ts`   | the settings from the environment                                    |
