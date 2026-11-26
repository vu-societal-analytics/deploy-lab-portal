// The end-to-end test of the lab portal, in a browser: login, membership (requests, invitations), access per
// service, 2FA, sign-out, back-channel logout, the API bypass, and settings reloads. Run by ./run.sh, which
// starts Keycloak (realm.json), Mailpit, the portal and Caddy first.
const { chromium } = require('playwright');
const crypto = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);

const KC = 'http://localhost:8080';
const MAIL = 'http://127.0.0.1:8025';
const PORTAL = 'https://lab.test';
const ADMIN_ID = 'e2e00000-0000-4000-8000-00000000ad01';
const PASSWORD = 'Passw0rd-123';
const WORK = `${__dirname}/.work`;

// ---- Small helpers
const failures = [];
let lastCheck = 'the start';
function check(name, ok, detail = '') {
  lastCheck = name;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok || !detail ? '' : `: ${detail}`}`);
  if (!ok) failures.push(name);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    const value = await fn().catch(() => undefined);
    if (value || Date.now() > end) return value;
    await sleep(500);
  }
}

/** The current code of the test user's authenticator app (RFC 6238). Keycloak uses the stored secret's
 *  characters as the key (an app would get them base32-encoded in the QR code). */
const OTP_SECRET = 'JBSWY3DPEHPK3PXP';
function totp() {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', Buffer.from(OTP_SECRET)).update(counter).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}

/** curl against Caddy (lab.test on 127.0.0.1), for requests a browser can't make. Not synchronous: the
 *  test services run in this process, and must be able to answer. */
async function curl(url, args = []) {
  const host = new URL(url).hostname;
  const { stdout: out } = await execFile('curl', ['-sk', '-m', '10', '--noproxy', '*', '--resolve', `${host}:443:127.0.0.1`, '-o', '-', '-w', '\n%{http_code} %{redirect_url}', ...args, url]);
  const lines = out.split('\n');
  const [status, location] = lines.pop().split(' ');
  return { status: Number(status), location, body: lines.join('\n') };
}

async function mails(to) {
  const r = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`, { signal: AbortSignal.timeout(5000) });
  return (await r.json()).messages ?? [];
}

async function kcAdmin(method, path) {
  const t = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin-e2e' }),
    signal: AbortSignal.timeout(10000),
  }).then((r) => r.json());
  const r = await fetch(`${KC}/admin/realms/test${path}`, { method, headers: { Authorization: `Bearer ${t.access_token}` }, signal: AbortSignal.timeout(10000) });
  return r.status === 204 ? null : r.json();
}

/** Test services: answer with what they received from Caddy */
function echo(name, port) {
  http
    .createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ service: name, path: req.url, user: req.headers['x-auth-request-user'] ?? null, email: req.headers['x-auth-request-email'] ?? null }));
    })
    .listen(port, '127.0.0.1')
    .unref();
}

/** Fills Keycloak's login form (the username is skipped when Keycloak asks to re-authenticate) */
async function keycloakLogin(page, email, { otp = false } = {}) {
  const stuck = async (step) => {
    const text = await page.locator('body').innerText().catch(() => '');
    throw new Error(`Signing in as ${email}, ${step}, at ${page.url()}: ${text.slice(0, 400)}`);
  };
  await page.waitForSelector('#password', { timeout: 15000 }).catch(() => stuck('no password field'));
  if (await page.locator('#username').isVisible().catch(() => false)) await page.fill('#username', email);
  await page.fill('#password', PASSWORD);
  await page.click('#kc-login');
  if (otp) {
    await page.waitForSelector('#otp', { timeout: 15000 }).catch(() => stuck('no one-time code field'));
    await page.fill('#otp', totp());
    await page.click('#kc-login');
  }
  await page.waitForURL((u) => !u.toString().startsWith(KC), { timeout: 15000 }).catch(() => stuck('still at the provider'));
}

const json = async (page) => JSON.parse(await page.locator('body').innerText());

// Never hang: give up after 8 minutes
setTimeout(() => {
  console.log(`FAIL the test took too long (after: ${lastCheck})`);
  process.exit(2);
}, 8 * 60_000).unref();

(async () => {
  echo('notes', 9001);
  echo('secret', 9002);
  echo('admintool', 9003);
  const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP lab.test 127.0.0.1, MAP *.lab.test 127.0.0.1'] });
  const person = async () => (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  const ids = {};
  try {
    // ---- Login, and the first admin
    const anon = await person();
    await anon.goto('https://notes.lab.test/');
    check('a service without a session sends to the login', anon.url().startsWith(`${KC}/realms/test/`));

    const admin = await person();
    await admin.goto(`${PORTAL}/`);
    await admin.click('a.button:has-text("Sign in")');
    await keycloakLogin(admin, 'admin@x.org', { otp: true });
    check('the admin (in admins.yml by account ID) sees the services', (await admin.locator('.services').innerText()).includes('Admin tool'));
    check('the account ID is shown', (await admin.locator('footer').innerText()).includes(ADMIN_ID));
    await admin.goto(`${PORTAL}/admin`);
    check('the admin page lists the admin, with the address from the login', (await admin.locator('main').innerText()).includes('Admin Test (admin@x.org)'));

    // ---- A membership request
    const applicant = await person();
    await applicant.goto('https://notes.lab.test/some/page');
    await keycloakLogin(applicant, 'applicant@x.org');
    check('a non-member is sent to the membership page', applicant.url().startsWith(`${PORTAL}/access`) && (await applicant.content()).includes('Request membership'));
    ids.applicant = (await applicant.locator('footer code').innerText()).trim();
    await applicant.fill('input[name=name]', 'Ann Applicant');
    await applicant.fill('textarea[name=message]', 'PhD student, X project');
    await applicant.click('button:has-text("Request membership")');
    check('the request is waiting', (await applicant.content()).includes('is waiting for a lab admin'));
    check('the admins get an email', !!(await until(async () => (await mails('admin@x.org')).find((m) => m.Subject === 'Lab membership requests'))));

    await admin.goto(`${PORTAL}/admin`);
    check('the admin page shows the request', (await admin.locator('main').innerText()).includes('PhD student, X project'));
    await admin.click('button:has-text("Approve")');
    check('approved: a welcome email', !!(await until(async () => (await mails('applicant@x.org')).find((m) => m.Subject.startsWith('Welcome')))));

    await applicant.goto('https://notes.lab.test/some/page');
    const seen = await json(applicant);
    check('the member reaches the service, which gets the account ID and the address', seen.user === ids.applicant && seen.email === 'applicant@x.org', JSON.stringify(seen));

    // ---- Access per service
    await applicant.goto('https://secret.lab.test/');
    check('mfa: required without a second factor: explained', applicant.url().startsWith(`${PORTAL}/mfa`) && (await applicant.content()).includes('requires a login with a second factor'));
    await applicant.click('a.button:has-text("Sign in with your second factor")');
    await keycloakLogin(applicant, 'applicant@x.org');
    check('after signing in again without one: how to add one', applicant.url().includes('retried=1') && (await applicant.content()).includes('has no second factor yet'));
    // A fresh login right after the last one must still be asked for (Keycloak skips max_age=0 within the second)
    await applicant.goto(`${PORTAL}/login?step_up=1&rd=${encodeURIComponent(`${PORTAL}/`)}`);
    check('a fresh login is asked for, also right after a login', applicant.url().startsWith(KC));
    await keycloakLogin(applicant, 'applicant@x.org');
    await applicant.goto('https://admintool.lab.test/');
    check('admins only: refused for a member', (await applicant.content()).includes('only for lab admins'));
    await applicant.goto(`${PORTAL}/admin`);
    check('the admin page: refused for a member', (await applicant.content()).includes('only for lab admins'));
    await admin.goto('https://secret.lab.test/');
    check('mfa: required, with a second factor: allowed', (await json(admin)).service === 'secret');
    await admin.goto('https://admintool.lab.test/');
    check('admins only: allowed for the admin', (await json(admin)).service === 'admintool');

    // ---- Invitations
    const invite = async (email, name) => {
      await admin.goto(`${PORTAL}/admin`);
      await admin.fill('form[action="/admin/invitations"] input[name=email]', email);
      await admin.fill('form[action="/admin/invitations"] input[name=name]', name);
      await admin.click('button:has-text("Invite")');
      return admin.locator('.note').innerText();
    };
    check('invite someone new', (await invite('Invitee@x.org', 'Ivy Invitee')).includes('Invitation sent to invitee@x.org'));
    check('the invitation is emailed', !!(await until(async () => (await mails('invitee@x.org')).find((m) => m.Subject.startsWith('Invitation')))));
    const invitee = await person();
    await invitee.goto(`${PORTAL}/login`);
    await keycloakLogin(invitee, 'invitee@x.org');
    check('the first sign-in with the invited, verified address: a member', (await invitee.locator('h1').innerText()) === 'Lab services');
    await admin.goto(`${PORTAL}/admin`);
    const adminPage = await admin.locator('main').innerText();
    check('the invitation is used up, and logged', !adminPage.includes('not signed in yet') && adminPage.includes('invited, joined'));

    await invite('unverified@x.org', 'Una Unverified');
    const unverified = await person();
    await unverified.goto(`${PORTAL}/login`);
    await keycloakLogin(unverified, 'unverified@x.org');
    check('an invited but unverified address: not a member', (await unverified.content()).includes('first verify your email address'));
    check('... and no request form', (await unverified.locator('form[action="/request"]').count()) === 0);

    // A request, rejected; then an invitation for someone who already signed in: a member at once
    const other = await person();
    await other.goto(`${PORTAL}/login`);
    await keycloakLogin(other, 'other@x.org');
    await other.fill('input[name=name]', 'Otto Other');
    await other.click('button:has-text("Request membership")');
    await admin.goto(`${PORTAL}/admin`);
    await admin.locator('tr', { hasText: 'other@x.org' }).locator('button:has-text("Reject")').click();
    await other.goto(`${PORTAL}/`);
    check('rejected: told so, no new request for a while', (await other.content()).includes('was not approved') && (await other.locator('form[action="/request"]').count()) === 0);
    check('invite someone who already signed in: a member at once', (await invite('other@x.org', 'Otto Other')).includes('is now a member'));
    await other.goto(`${PORTAL}/`);
    check('... and they see the services', (await other.locator('h1').innerText()) === 'Lab services');

    // ---- Requests from other sites, the API bypass, forged headers
    check('a form post from another site is refused (CSRF)', (await curl(`${PORTAL}/admin/invitations`, ['-X', 'POST', '-H', 'Origin: https://evil.test', '-d', 'email=x@x.org&name=X'])).status === 403);
    const api = await curl('https://notes.lab.test/api/items', ['-H', 'Authorization: Bearer the-services-own-key', '-H', 'X-Auth-Request-Email: forged@x.org']);
    check('API path with an Authorization header: reaches the service', api.status === 200 && JSON.parse(api.body).service === 'notes');
    check('... and forged identity headers are removed', JSON.parse(api.body).email === null);
    check('API path without an Authorization header: login', (await curl('https://notes.lab.test/api/items')).status === 302);
    check('other paths with an Authorization header: login', (await curl('https://notes.lab.test/page', ['-H', 'Authorization: Bearer x'])).status === 302);
    check('the authorization endpoint is closed on the portal site', (await curl(`${PORTAL}/auth`)).status === 404);

    // ---- Settings: a new service; an invalid file keeps the previous settings
    const servicesFile = `${WORK}/config/services.yml`;
    const services = fs.readFileSync(servicesFile, 'utf8');
    fs.writeFileSync(servicesFile, `${services}  late:\n    name: Late\n    upstream: 127.0.0.1:9003\n    mfa: optional\n`);
    const late = await until(async () => {
      await applicant.goto('https://late.lab.test/');
      return (await json(applicant)).service === 'admintool';
    }, 20000);
    check('a new service in services.yml works within seconds', !!late);
    fs.writeFileSync(servicesFile, `${services}  broken:\n    upstream: nope\n`);
    await sleep(5000);
    await applicant.goto('https://late.lab.test/');
    check('an invalid services.yml: the previous settings stay', (await json(applicant)).service === 'admintool');
    fs.writeFileSync(servicesFile, services);

    // ---- Removing a member: at once
    await admin.goto(`${PORTAL}/admin`);
    await admin.locator('tr', { hasText: 'applicant@x.org' }).locator('button:has-text("Remove")').click();
    await applicant.goto('https://notes.lab.test/');
    // their session ended with the removal; the provider may still remember them, or ask for the password
    if (applicant.url().startsWith(KC)) await keycloakLogin(applicant, 'applicant@x.org');
    check('a removed member loses access at once', (await applicant.content()).includes('only for lab members'));

    // ---- Signing out, here and at the provider
    await invitee.click('button:has-text("Sign out")');
    await invitee.waitForURL(`${PORTAL}/signed-out`);
    await invitee.goto('https://notes.lab.test/');
    check('signed out: the next visit asks for the password again', invitee.url().startsWith(KC) && (await invitee.locator('#password').count()) === 1);
    await keycloakLogin(invitee, 'invitee@x.org');
    const user = (await kcAdmin('GET', '/users?email=invitee@x.org'))[0];
    await kcAdmin('POST', `/users/${user.id}/logout`);
    await sleep(1000);
    await invitee.goto('https://notes.lab.test/');
    check('signed out at the provider: the portal session ends too (back-channel logout)', invitee.url().startsWith(KC));

    // ---- The portal's own session outlives the provider's (60 seconds idle in this realm)
    console.log('... waiting 70 seconds (the provider session expires)');
    await sleep(70000);
    await other.goto('https://notes.lab.test/');
    check("the portal's session outlives the provider's", (await json(other)).service === 'notes');

    // ---- The daily copy of the database
    check('a copy of the database is in backups/', fs.readdirSync(`${WORK}/backups`).some((f) => /^portal-\d{4}-\d{2}-\d{2}\.db$/.test(f)));
  } catch (error) {
    check('no unexpected errors', false, error.stack);
  } finally {
    await browser.close();
  }
  console.log(failures.length ? `\n${failures.length} FAILED` : '\nALL PASSED');
  process.exit(failures.length ? 1 : 0);
})();
