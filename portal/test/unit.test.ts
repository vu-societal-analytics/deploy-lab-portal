import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, safeReturnUrl } from '../src/authz.ts';
import { parseServices, parseGroups, type Service } from '../src/settings.ts';
import { renderCaddyfile } from '../src/caddy.ts';
import { hasMfa } from '../src/oidc.ts';

const D = 'lab.example.org';
const svc = (over: Partial<Service> = {}): Service => ({
  id: 'whisper', host: `whisper.${D}`, name: 'Whisper', description: '', upstream: '127.0.0.1:9000',
  access: 'members', mfa: 'optional', apiBypass: [], show: true, ...over,
});
const m = { isAdmin: (e: string) => e === 'admin@x.org', isMember: (e: string) => e === 'member@x.org' };
const rules = { insecureDisable2fa: false, insecureDisableEmailVerification: false };
const who = (email: string, over = {}) => ({ email, emailVerified: true, hasMfa: false, ...over });

test('access rules', () => {
  assert.equal(decide(svc(), null, m, rules).result, 'login');
  assert.equal(decide(svc(), who('member@x.org'), m, rules).result, 'allow');
  assert.equal(decide(svc(), who('admin@x.org'), m, rules).result, 'allow', 'admins are members');
  assert.equal(decide(svc(), who('other@x.org'), m, rules).result, 'not-member');
  assert.equal(decide(svc(), who('member@x.org', { emailVerified: false }), m, rules).result, 'unverified');
  assert.equal(decide(svc({ access: 'admins' }), who('member@x.org'), m, rules).result, 'not-admin');
  assert.equal(decide(svc({ access: 'admins' }), who('admin@x.org'), m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('member@x.org'), m, rules).result, 'mfa');
  assert.equal(decide(svc({ mfa: 'required' }), who('member@x.org', { hasMfa: true }), m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('other@x.org', { hasMfa: true }), m, rules).result, 'not-member', 'membership before 2FA');
  assert.equal(decide(svc({ access: 'public' }), null, m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('member@x.org'), m, { ...rules, insecureDisable2fa: true }).result, 'allow');
  assert.equal(decide(svc(), who('member@x.org', { emailVerified: false }), m, { ...rules, insecureDisableEmailVerification: true }).result, 'allow');
});

test('only addresses in the lab zone to return to', () => {
  const home = `https://${D}/`;
  assert.equal(safeReturnUrl(`https://whisper.${D}/x?y=1`, D), `https://whisper.${D}/x?y=1`);
  assert.equal(safeReturnUrl(`https://${D}/admin`, D), `https://${D}/admin`);
  for (const bad of [`https://evil.org/`, `https://${D}.evil.org/`, `http://whisper.${D}/`, `https://evil${D}/`,
    `https://user:pw@whisper.${D}/`, `https://whisper.${D}:8443/`, `//evil.org`, `javascript:alert(1)`, undefined, ''])
    assert.equal(safeReturnUrl(bad as any, D), home, String(bad));
});

test('services.yml', () => {
  const s = parseServices(`services:\n  whisper:\n    upstream: 127.0.0.1:9000\n    mfa: required\n    api_bypass: [/api/*]\n    max_upload: 2.5GB\n    timeout: 3000s\n`, D);
  assert.equal(s[0].host, `whisper.${D}`);
  assert.equal(s[0].access, 'members');
  for (const bad of [
    'services:\n  Bad_Name:\n    upstream: 127.0.0.1:1',
    'services:\n  a:\n    upstream: nope',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    access: everyone',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    typo: 1',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    access: public\n    mfa: required',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    api_bypass: [api]',
    'services:\n  a:\n    upstream: "127.0.0.1:1\\n}\\nevil {"',
  ]) assert.throws(() => parseServices(bad, D), undefined, bad);
});

test('groups.yml', () => {
  const g = parseGroups('admin:\n  - Admin@X.org\nlab:\n  - a@x.org\n');
  assert.deepEqual(g, { admin: ['admin@x.org'], lab: ['a@x.org'] });
  assert.throws(() => parseGroups('admin: []\n'));
  assert.throws(() => parseGroups('admin: [a@x.org]\nstaff: [b@x.org]\n'));
  assert.throws(() => parseGroups('admin: [not-an-email]\n'));
});

test('Caddyfile', () => {
  const services = parseServices(`services:\n  whisper:\n    upstream: 127.0.0.1:9000\n    api_bypass: [/api/*]\n    timeout: 300s\n  open:\n    upstream: 127.0.0.1:9001\n    access: public\n`, D);
  const f = renderCaddyfile(services, { labDomain: D, portalUpstream: '127.0.0.1:3000', acmeEmail: 'a@x.org' });
  assert.match(f, new RegExp(`^${D} \\{[\\s\\S]*respond @auth 404`, 'm'), 'the authorization endpoint is closed on the portal site');
  assert.match(f, /whisper\.lab\.example\.org \{\n\trequest_header -X-Auth-Request-Email\n\trequest_header -X-Auth-Request-User/);
  assert.match(f, /@api \{\n\t\tpath \/api\/\*\n\t\theader Authorization \*/);
  assert.match(f, /forward_auth 127\.0\.0\.1:3000 \{\n\t\t\turi \/auth/);
  const open = f.slice(f.indexOf('open.lab'));
  assert.doesNotMatch(open, /forward_auth/, 'public: no lab login');
});

test('2FA claim', () => {
  assert.equal(hasMfa({ amr: ['pwd', 'mfa'] }, { claim: 'amr', value: 'mfa' }), true);
  assert.equal(hasMfa({ amr: ['pwd'] }, { claim: 'amr', value: 'mfa' }), false);
  assert.equal(hasMfa({ amr: 'mfa' }, { claim: 'amr', value: 'mfa' }), false);
  assert.equal(hasMfa({ acr: 'loa2' }, { claim: 'acr', value: 'loa2' }), true);
});

test('daily database copy: consistent, without sessions, 7 kept', async () => {
  const { Db } = await import('../src/db.ts');
  const { mkdtempSync, readdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { DatabaseSync } = await import('node:sqlite');
  const dir = mkdtempSync(`${tmpdir()}/portal-`);
  const db = new Db(`${dir}/portal.db`);
  db.addMember('a@x.org', 'A', 'admin@x.org');
  db.insertSession({ id: 'h', email: 'a@x.org', sub: 's', sid: null, email_verified: 1, has_mfa: 0, auth_at: 0, id_token: 't', refresh_token: 'r', created_at: 0, last_seen: 0, checked_at: 0 });
  for (let d = 1; d <= 9; d++) db.backup(`${dir}/backups`, 7, new Date(Date.UTC(2026, 0, d)));
  assert.equal(db.backup(`${dir}/backups`, 7, new Date(Date.UTC(2026, 0, 9))), null, 'once a day');
  const files = readdirSync(`${dir}/backups`).sort();
  assert.deepEqual(files, [3, 4, 5, 6, 7, 8, 9].map((d) => `portal-2026-01-0${d}.db`));
  const copy = new DatabaseSync(`${dir}/backups/${files.at(-1)}`);
  assert.equal((copy.prepare('SELECT count(*) n FROM members').get() as { n: number }).n, 1);
  assert.equal((copy.prepare('SELECT count(*) n FROM sessions').get() as { n: number }).n, 0);
});
