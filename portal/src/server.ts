// Starts the portal: reads the settings, writes the Caddyfile, and serves the portal.
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { loadConfig } from './config.js';
import { Db } from './db.js';
import { Settings } from './settings.js';
import { Oidc } from './oidc.js';
import { Mail } from './mail.js';
import { renderCaddyfile, writeCaddyfile } from './caddy.js';
import { createApp } from './app.js';

const cfg = loadConfig();
if (cfg.insecureDisable2fa) console.warn('WARNING: AUTH_INSECURE_DISABLE_2FA is on: admin changes and services with mfa: required no longer need a second factor.');
if (cfg.insecureDisableEmailVerification) console.warn('WARNING: AUTH_INSECURE_DISABLE_EMAIL_VERIFICATION is on: unverified email addresses are accepted.');

const settings = new Settings(cfg.servicesFile, cfg.adminsFile, cfg.labDomain);
const caddy = () => {
  if (writeCaddyfile(cfg.caddyFile, renderCaddyfile(settings.services, cfg, settings.redirects))) console.log(`Caddyfile written: ${settings.services.length} service(s), ${settings.redirects.length} redirect(s)`);
};
caddy();
settings.onChange = caddy;

const db = new Db(cfg.databaseFile);

// The provider may not be reachable yet (e.g. both start at the same time): keep trying
let oidc: Oidc | undefined;
for (let attempt = 1; !oidc; attempt++) {
  try {
    oidc = await Oidc.create(cfg);
  } catch (error) {
    console.error(`OIDC provider not reachable (${(error as Error).message}), retrying (${attempt})`);
    await new Promise((r) => setTimeout(r, Math.min(30, attempt * 2) * 1000));
  }
}

const issuer = oidc.issuer;
const mail = new Mail(cfg, db, () => db.emailsOf(settings.admins.map((a) => a.sub), issuer));
const app = new Hono();
app.use('/static/*', serveStatic({ root: './public', rewriteRequestPath: (p) => p.replace(/^\/static/, '') }));
app.route('/', createApp({ cfg, db, settings, oidc, mail }));

const backup = () => {
  if (!cfg.backupDir) return;
  try {
    const file = db.backup(cfg.backupDir);
    if (file) console.log(`Database copied to ${file}`);
  } catch (error) {
    console.error(`Database backup failed: ${(error as Error).message}`);
  }
};
backup();
setInterval(() => {
  const longest = settings.longestSession({ idle: cfg.sessionIdle, max: cfg.sessionMax });
  db.purgeSessions(longest.idle, longest.max);
  backup();
}, 3600_000).unref();
setInterval(() => {
  settings.refresh();
  void mail.tick();
}, 60_000).unref();

serve({ fetch: app.fetch, hostname: cfg.listenHost, port: cfg.listenPort }, (info) =>
  console.log(`Lab portal on ${cfg.portalUrl} (listening on ${info.address}:${info.port})`),
);
