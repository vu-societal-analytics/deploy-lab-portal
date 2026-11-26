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
Admin changes always need a login with a second factor from the last 10 minutes
(`AUTH_STEP_UP_MAX_AGE`); the admin page asks to sign in again otherwise.

`api_bypass` lists paths where requests **with an `Authorization` header** skip the lab login, so
scripts can use the service's own API keys. Only for services that check those keys themselves.

### Sessions

One sign-in for the whole lab zone (a cookie on `lab.<domain>`, holding a random token; the database
only has its hash). The portal keeps its own sessions, like AmCAT and AnnoTinder: a session ends after
12 hours without use or 7 days in total (`SESSION_IDLE`, `SESSION_MAX`), on sign-out (which also signs
out at the provider), or when the person signs out at the provider (back-channel logout). Removing a
member takes effect at once. To lock someone out completely, also sign them out (or disable them) in
Keycloak.

## Setup

On the lab server, as `sal`, in `/opt/lab-portal`:

1. **Keycloak**: in the realm (the one AmCAT and AnnoTinder use), create the client `lab-portal`:
   - Client authentication **on** (confidential), Standard flow only, PKCE method **S256**
   - Valid redirect URI: `https://<LAB_DOMAIN>/callback`
   - Valid post logout redirect URI: `https://<LAB_DOMAIN>/signed-out`
   - Front channel logout **off**; Backchannel logout URL: `https://<LAB_DOMAIN>/backchannel-logout`,
     Backchannel logout session required **on**
   - Copy the client secret (Credentials tab).

   The portal needs the claims `email`, `email_verified` and `amr` (with `mfa` after a second factor).
2. **Settings**:
   ```bash
   cp .env.example .env && chmod 600 .env          # fill in: LAB_DOMAIN, OIDC_*, SMTP_*
   cp config/services.example.yml config/services.yml
   cp config/admins.example.yml config/admins.yml
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
5. **The first admin**: sign in on `https://<LAB_DOMAIN>`, copy the account ID from the bottom of the
   page into `config/admins.yml` (replacing the example), and reload the page: the **Admin** link appears.

## Daily use

- **Members**: on `https://<LAB_DOMAIN>/admin`: approve or reject requests, invite people by email
  address, remove members.
- **Add or change a service**: edit `config/services.yml`. The portal checks the file; when it is
  invalid it keeps the previous settings and logs why (`docker compose logs portal`).
- **An old address that moved** (e.g. under `lab.`): add it under `redirects:` in `services.yml`.
- **Admins**: edit `config/admins.yml`.
- **Update**: `git pull && docker compose up -d --build`. If the portal then refuses to start with
  "has database version", the database format changed: see the release notes of that version.

## Settings (.env)

See `.env.example`. Besides those, for tests only: `AUTH_INSECURE_DISABLE_2FA`,
`AUTH_INSECURE_DISABLE_EMAIL_VERIFICATION` (the lab's Authentication standard), and
`TEST_ALLOW_HTTP_ISSUER`, `TEST_LOCAL_CERTS`.

## Development and tests

```bash
cd portal
npm ci
npm test            # unit tests: access rules, settings, Caddyfile, users and members, email, backups
```

**End-to-end test** (`test/e2e`): Keycloak with a minimal realm (`realm.json`: only what the
Authentication standard asks of a provider, not our production realm), a mail catcher, the portal's
Docker image and Caddy, and a browser that goes through login, requests, invitations, access per
service, 2FA, sign-out, back-channel logout, the API bypass and settings reloads. Takes about 3 minutes;
uses ports 80, 443, 1025, 3000, 8025 and 8080 on this machine (not on the server).

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
| `oidc.ts`     | OIDC login (PKCE, state, nonce), sign-out, back-channel logout tokens    |
| `settings.ts` | reads and validates services.yml and admins.yml, reloads on change       |
| `caddy.ts`    | the Caddyfile from services.yml                                          |
| `db.ts`       | the SQLite database and its daily copy                                   |
| `mail.ts`     | notifications to admins (throttled, daily reminder), invitations, welcome |
| `views.tsx`   | the pages                                                                |
| `config.ts`   | the settings from the environment                                        |
