# Development mode

The portal on your own computer, to try a change: no Keycloak, no Caddy, no Docker. Needs Node 24.

```bash
cd portal
npm ci
npm run dev
```

Then open **http://localhost:3000**. The portal restarts whenever you save a file in `portal/src`.

This is the portal's `AUTH_DEV_MODE` (the lab's Authentication standard): there is no OIDC provider,
and "Sign in" shows a form where you type any email address, with or without a second factor. In
development mode the account ID is that email address. The portal refuses to start in development mode
unless it listens only on this computer (127.0.0.1); never use it on a server.

- **The admin** is `admin@example.org` (in `config/admins.yml`). Admin changes need a sign-in with
  the second factor ticked.
- **Emails** (invitations, notifications to the admins) are printed in the terminal, not sent.
- **The services** in `config/services.yml` show up in the overview, but their links don't open
  anything: without Caddy nothing sits in front of them. The access rules for the services, Caddy and a
  real Keycloak login are covered by the end-to-end test (`test/e2e/run.sh`).

| File | What |
| --- | --- |
| `portal.env` | The portal's settings in development mode |
| `config/services.yml` | Example services. Edit it while the portal runs: it reloads within seconds |
| `config/admins.yml` | The admin |
| `.work/` | The portal's database (not in git). Delete it to start over |
