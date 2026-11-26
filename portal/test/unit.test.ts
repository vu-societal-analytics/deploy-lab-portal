import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, safeReturnUrl } from '../src/authz.ts';
import { parseServices, parseAdmins, parseRedirects, type Service } from '../src/settings.ts';
import { renderCaddyfile } from '../src/caddy.ts';
import { hasMfa } from '../src/oidc.ts';

const D = 'lab.example.org';
const svc = (over: Partial<Service> = {}): Service => ({
  id: 'whisper', host: `whisper.${D}`, name: 'Whisper', description: '', upstream: '127.0.0.1:9000',
  access: 'members', mfa: 'optional', apiBypass: [], show: true, ...over,
});
const ISS = 'https://id.example.org/realms/idp';
const m = { isAdmin: (p: { sub: string }) => p.sub === 'admin', isMember: (p: { sub: string }) => p.sub === 'member' };
const rules = { insecureDisable2fa: false };
const who = (sub: string, over = {}) => ({ iss: ISS, sub, hasMfa: false, ...over });

test('access rules', () => {
  assert.equal(decide(svc(), null, m, rules).result, 'login');
  assert.equal(decide(svc(), who('member'), m, rules).result, 'allow');
  assert.equal(decide(svc(), who('admin'), m, rules).result, 'allow', 'admins are members');
  assert.equal(decide(svc(), who('other'), m, rules).result, 'not-member');
  assert.equal(decide(svc({ access: 'admins' }), who('member'), m, rules).result, 'not-admin');
  assert.equal(decide(svc({ access: 'admins' }), who('admin'), m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('member'), m, rules).result, 'mfa');
  assert.equal(decide(svc({ mfa: 'required' }), who('member', { hasMfa: true }), m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('other', { hasMfa: true }), m, rules).result, 'not-member', 'membership before 2FA');
  assert.equal(decide(svc({ access: 'public' }), null, m, rules).result, 'allow');
  assert.equal(decide(svc({ mfa: 'required' }), who('member'), m, { insecureDisable2fa: true }).result, 'allow');
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
  assert.equal(parseServices('services:\n  a:\n    upstream: 127.0.0.1:1\n    access: public\n', D)[0].mfa, 'optional');
  assert.throws(() => parseServices('services:\n  a:\n    upstream: 127.0.0.1:1\n', D), /set mfa/, 'mfa must be chosen');
  for (const bad of [
    'services:\n  Bad_Name:\n    upstream: 127.0.0.1:1\n    mfa: optional',
    'services:\n  a:\n    upstream: nope\n    mfa: optional',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    access: everyone\n    mfa: optional',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    mfa: optional\n    typo: 1',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    mfa: sometimes',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    access: public\n    mfa: required',
    'services:\n  a:\n    upstream: 127.0.0.1:1\n    mfa: optional\n    api_bypass: [api]',
    'services:\n  a:\n    upstream: "127.0.0.1:1\\n}\\nevil {"\n    mfa: optional',
  ]) assert.throws(() => parseServices(bad, D), undefined, bad);
});

test('admins.yml', () => {
  assert.deepEqual(parseAdmins('admins:\n  0b6c7e1a-55c4-4f5e-9d3b-1e2f3a4b5c6d: Jane Doe\n'), [
    { sub: '0b6c7e1a-55c4-4f5e-9d3b-1e2f3a4b5c6d', name: 'Jane Doe' },
  ]);
  assert.throws(() => parseAdmins('admins: {}\n'), /at least one/);
  assert.throws(() => parseAdmins('admins:\n  abc: Jane\nlab: []\n'), /unknown section/);
  assert.throws(() => parseAdmins('admins:\n  "abc def": Jane\n'), /not an account ID/);
  assert.throws(() => parseAdmins('admins:\n  abc:\n'), /give a name/);
  assert.throws(() => parseAdmins('admins:\n  - abc\n'), /map/);
});

test('Caddyfile', () => {
  const services = parseServices(`services:\n  whisper:\n    upstream: 127.0.0.1:9000\n    mfa: optional\n    api_bypass: [/api/*]\n    timeout: 300s\n  open:\n    upstream: 127.0.0.1:9001\n    access: public\n`, D);
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
  const a = { iss: ISS, sub: 'a' };
  db.upsertUser(a, 'a@x.org', true);
  db.addMember(a, 'Admin');
  db.insertSession({ id: 'h', ...a, sid: null, email: 'a@x.org', email_verified: 1, has_mfa: 0, auth_at: 0, id_token: 't', created_at: 0, last_seen: 0 });
  for (let d = 1; d <= 9; d++) db.backup(`${dir}/backups`, 7, new Date(Date.UTC(2026, 0, d)));
  assert.equal(db.backup(`${dir}/backups`, 7, new Date(Date.UTC(2026, 0, 9))), null, 'once a day');
  const files = readdirSync(`${dir}/backups`).sort();
  assert.deepEqual(files, [3, 4, 5, 6, 7, 8, 9].map((d) => `portal-2026-01-0${d}.db`));
  const copy = new DatabaseSync(`${dir}/backups/${files.at(-1)}`);
  assert.equal((copy.prepare('SELECT count(*) n FROM members').get() as { n: number }).n, 1);
  assert.equal((copy.prepare('SELECT count(*) n FROM sessions').get() as { n: number }).n, 0);
});

test('redirects: validated, rendered as permanent redirects', () => {
  const yml = `services:\n  whisper:\n    upstream: 127.0.0.1:9000\n    mfa: optional\nredirects:\n  whisper.example.org: https://whisper.${D}\n`;
  const services = parseServices(yml, D);
  const r = parseRedirects(yml, D, services);
  assert.deepEqual(r, [{ from: 'whisper.example.org', to: `https://whisper.${D}` }]);
  const f = renderCaddyfile(services, { labDomain: D, portalUpstream: '127.0.0.1:3000', acmeEmail: '' }, r);
  assert.match(f, /whisper\.example\.org \{\n\tredir https:\/\/whisper\.lab\.example\.org\{uri\} permanent\n\}/);
  for (const bad of [
    `redirects:\n  whisper.${D}: https://x.org`, // a service's own address
    `redirects:\n  ${D}: https://x.org`, // the portal
    `redirects:\n  old.example.org: http://x.org`, // not https
    `redirects:\n  old.example.org: https://x.org/path`, // not an origin
    `redirects:\n  old.example.org: "https://x.org {\\n}"`, // injection
    `redirects:\n  "old.example.org {": https://x.org`,
  ]) assert.throws(() => parseRedirects(`services:\n  whisper:\n    upstream: 127.0.0.1:9000\n    mfa: optional\n${bad}\n`, D, services), undefined, bad);
  assert.throws(() => parseServices(`servics:\n  a: {}\n`, D), /unknown section/);
});

test('users by issuer and account ID: the email address can change, membership stays', async () => {
  const { Db } = await import('../src/db.ts');
  const db = new Db(':memory:');
  const a = { iss: ISS, sub: 'a' };
  db.upsertUser(a, 'old@x.org', true);
  db.addMember(a, 'Admin');
  db.upsertUser(a, 'new@x.org', false);
  assert.equal(db.isMember(a), true);
  assert.equal(db.members()[0].email, 'new@x.org');
  assert.equal(db.isMember({ iss: 'https://other.example.org', sub: 'a' }), false, 'another issuer is another person');
  assert.equal(db.userByVerifiedEmail('new@x.org'), undefined, 'not verified');
  db.upsertUser(a, 'new@x.org', true);
  assert.equal(db.userByVerifiedEmail('new@x.org')?.sub, 'a');
  assert.deepEqual(db.emailsOf(['a', 'unknown'], ISS), ['new@x.org']);
  db.addRequest(a, 'A', 'hi');
  assert.equal(db.pendingRequests()[0].email, 'new@x.org');
  db.settleRequestsOf(a, 'Admin');
  assert.equal(db.pendingRequests().length, 0);
  assert.equal(db.lastRequestOf(a)?.status, 'approved');
});

test('an older database is refused, not silently changed', async () => {
  const { Db } = await import('../src/db.ts');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { DatabaseSync } = await import('node:sqlite');
  const file = `${mkdtempSync(`${tmpdir()}/portal-`)}/old.db`;
  new DatabaseSync(file).exec('CREATE TABLE members (email TEXT PRIMARY KEY)');
  assert.throws(() => new Db(file), /database version 0/);
});
