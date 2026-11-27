import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.ts';
import { createApp, DEV_ISSUER } from '../src/app.tsx';
import { Db } from '../src/db.ts';
import { Settings } from '../src/settings.ts';
import { Mail } from '../src/mail.ts';

/** loadConfig with only these settings in the environment */
function configWith(vars: Record<string, string>) {
  const saved = { ...process.env };
  for (const k of Object.keys(process.env)) if (/^(AUTH_|PORTAL_|LAB_|OIDC_|SMTP_)/.test(k)) delete process.env[k];
  Object.assign(process.env, vars);
  try {
    return loadConfig();
  } finally {
    process.env = saved;
  }
}

test('development mode: only when listening on localhost', () => {
  assert.throws(() => configWith({ AUTH_DEV_MODE: 'true', PORTAL_LISTEN_HOST: '0.0.0.0' }), /only allowed when the portal listens on localhost/);
  assert.throws(() => configWith({ AUTH_DEV_MODE: 'true', PORTAL_LISTEN_HOST: '192.168.1.10' }), /localhost/);
  const cfg = configWith({ AUTH_DEV_MODE: 'true' });
  assert.equal(cfg.listenHost, '127.0.0.1', 'localhost by default');
  assert.equal(cfg.portalUrl, 'http://localhost:3000');
  assert.equal(configWith({ AUTH_DEV_MODE: 'true', PORTAL_LISTEN_HOST: '::1' }).listenHost, '::1');
  assert.throws(() => configWith({}), /Missing setting/, 'without development mode the provider is required');
});

test('development mode: sign in as any address, with or without a second factor', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'portal-dev-'));
  writeFileSync(join(dir, 'services.yml'), 'services: {}\n');
  writeFileSync(join(dir, 'admins.yml'), 'admins:\n  admin@example.org: Admin Dev\n');
  const cfg = configWith({ AUTH_DEV_MODE: 'true', SERVICES_FILE: join(dir, 'services.yml'), ADMINS_FILE: join(dir, 'admins.yml'), DATABASE_FILE: ':memory:' });
  const db = new Db(':memory:');
  const settings = new Settings(cfg.servicesFile, cfg.adminsFile, cfg.labDomain);
  const app = createApp({ cfg, db, settings, issuer: DEV_ISSUER, mail: new Mail(cfg, db, () => []) });
  const origin = { Origin: cfg.portalUrl, 'Content-Type': 'application/x-www-form-urlencoded' };

  const form = await app.request('/login?rd=' + encodeURIComponent(`${cfg.portalUrl}/admin`));
  assert.equal(form.status, 200);
  assert.match(await form.text(), /Development mode/);

  const signIn = (body: string) => app.request('/login', { method: 'POST', headers: origin, body });
  const res = await signIn(`email=admin%40example.org&mfa=on&rd=${encodeURIComponent(`${cfg.portalUrl}/admin`)}`);
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), `${cfg.portalUrl}/admin`);
  const cookie = res.headers.get('set-cookie')!;
  assert.doesNotMatch(cookie, /Secure|Domain/i, 'a cookie for http://localhost');
  const admin = await app.request('/admin', { headers: { Cookie: cookie.split(';')[0] } });
  assert.equal(admin.status, 200, 'the admin (by email address in development mode) with a second factor');

  const other = await signIn('email=someone%40example.org&rd=https%3A%2F%2Fevil.example');
  assert.equal(other.headers.get('location'), `${cfg.portalUrl}/`, 'only return to the portal itself');
  assert.equal((await signIn('email=nonsense')).headers.get('location'), '/login');
  const crossSite = await app.request('/login', { method: 'POST', headers: { ...origin, Origin: 'https://evil.example' }, body: 'email=a%40b.org' });
  assert.equal(crossSite.status, 403, 'no sign-in from another site');
});
