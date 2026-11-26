/** @jsxImportSource hono/jsx */
// The portal's routes: the login, the authorization endpoint for Caddy (/auth), the overview of the services,
// membership requests, and the admin page.
import { Hono, type Context } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { csrf } from 'hono/csrf';
import { secureHeaders } from 'hono/secure-headers';
import { createHash, randomBytes } from 'node:crypto';
import type { Config } from './config.js';
import type { Db, SessionRow } from './db.js';
import type { Settings } from './settings.js';
import type { Oidc } from './oidc.js';
import type { Mail } from './mail.js';
import { decide, isLabMember, safeReturnUrl, type Person } from './authz.js';
import * as V from './views.js';

const SESSION_COOKIE = 'lab_session';
const LOGIN_COOKIE = 'lab_login';
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const hash = (token: string) => createHash('sha256').update(token).digest('hex');
const now = () => Math.floor(Date.now() / 1000);

export type Deps = { cfg: Config; db: Db; settings: Settings; oidc: Oidc; mail: Mail };

export function createApp({ cfg, db, settings, oidc, mail }: Deps) {
  const app = new Hono();
  const membership = { isAdmin: (e: string) => settings.isAdmin(e), isMember: (e: string) => settings.groups.lab.includes(e) || db.isMember(e) };
  const rules = { insecureDisable2fa: cfg.insecureDisable2fa, insecureDisableEmailVerification: cfg.insecureDisableEmailVerification };
  const portal = (path: string) => `${cfg.portalUrl}${path}`;

  /** The signed-in person, or null. Checks idle and maximum age, and checks with the provider every few minutes. */
  async function session(c: Context): Promise<SessionRow | null> {
    const token = getCookie(c, SESSION_COOKIE);
    if (!token) return null;
    const id = hash(token);
    const row = db.getSession(id);
    if (!row) return null;
    const t = now();
    if (t - row.last_seen > cfg.sessionIdle || t - row.created_at > cfg.sessionMax) {
      db.deleteSession(id);
      return null;
    }
    if (t - row.checked_at > cfg.sessionCheck && row.refresh_token) {
      const result = await oidc.refresh(row.refresh_token).catch(() => undefined);
      if (result === null) {
        // the session at the provider ended (signed out, expired, user removed)
        db.deleteSession(id);
        return null;
      }
      if (result) db.updateSessionTokens(id, result.refreshToken, result.idToken);
    }
    if (t - row.last_seen > 60) db.touchSession(id);
    return row;
  }

  const person = (s: SessionRow): Person => ({ email: s.email, emailVerified: !!s.email_verified, hasMfa: !!s.has_mfa });
  const ctx = (s?: SessionRow | null): V.Ctx => ({
    labName: cfg.labName,
    accountUrl: cfg.accountUrl,
    registrationOpen: cfg.registrationOpen,
    email: s?.email,
    isAdmin: s ? settings.isAdmin(s.email) : false,
  });
  /** Admin changes need a 2FA login of at most AUTH_STEP_UP_MAX_AGE seconds ago (with insecure 2FA: a recent login). */
  const recentStepUp = (s: SessionRow) => (cfg.insecureDisable2fa || !!s.has_mfa) && now() - s.auth_at <= cfg.stepUpMaxAge;
  const loginUrl = (rd: string, stepUp = false) => portal(`/login?rd=${encodeURIComponent(rd)}${stepUp ? '&step_up=1' : ''}`);

  app.use('*', async (_c, next) => {
    settings.refresh();
    await next();
  });
  app.use('/static/*', async (c, next) => {
    await next();
    c.header('Cache-Control', 'public, max-age=3600');
  });
  // Pages: no framing, no inline scripts, same-origin forms only
  for (const path of ['/', '/login', '/callback', '/logout', '/signed-out', '/access', '/mfa', '/request', '/admin', '/admin/*'])
    app.use(path, secureHeaders({ contentSecurityPolicy: { defaultSrc: ["'self'"], formAction: ["'self'", new URL(cfg.oidcHost).origin], frameAncestors: ["'none'"] } }));
  for (const path of ['/logout', '/request', '/admin/*']) app.use(path, csrf({ origin: cfg.portalUrl }));

  app.get('/health', (c) => c.text('ok'));

  // ---- Authorization endpoint for Caddy (forward_auth): only reachable from Caddy, not through the portal's site
  app.get('/auth', async (c) => {
    const host = (c.req.header('X-Forwarded-Host') ?? '').toLowerCase();
    const uri = c.req.header('X-Forwarded-Uri') ?? '/';
    const service = settings.serviceForHost(host);
    if (!service) return c.text('Unknown service', 403);
    const original = `https://${host}${uri.startsWith('/') ? uri : '/'}`;
    const s = await session(c);
    const decision = decide(service, s ? person(s) : null, membership, rules);
    switch (decision.result) {
      case 'allow':
        if (s) {
          c.header('X-Auth-Request-Email', s.email);
          c.header('X-Auth-Request-User', s.sub);
        }
        return c.body(null, 200);
      case 'login':
        return c.redirect(loginUrl(original), 302);
      case 'mfa':
        return c.redirect(portal(`/mfa?rd=${encodeURIComponent(original)}`), 302);
      default:
        return c.redirect(portal(`/access?service=${encodeURIComponent(service.id)}&reason=${decision.result}`), 302);
    }
  });

  // ---- Login
  app.get('/login', async (c) => {
    const rd = safeReturnUrl(c.req.query('rd') ?? portal('/'), cfg.labDomain);
    const stepUp = c.req.query('step_up') === '1';
    const start = await oidc.start(stepUp ? 0 : undefined);
    db.insertLogin({ state: start.state, nonce: start.nonce, verifier: start.verifier, rd, step_up: stepUp ? 1 : 0, created_at: now() });
    setCookie(c, LOGIN_COOKIE, start.state, { path: '/callback', httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 900 });
    return c.redirect(start.url, 302);
  });

  app.get('/callback', async (c) => {
    const state = c.req.query('state') ?? '';
    const cookieState = getCookie(c, LOGIN_COOKIE);
    deleteCookie(c, LOGIN_COOKIE, { path: '/callback', secure: true });
    const login = state && cookieState === state ? db.takeLogin(state) : undefined;
    if (!login) return c.html(<V.Message ctx={ctx()} title="Sign-in expired"><p><a href="/login">Sign in again</a>.</p></V.Message>, 400);
    if (c.req.query('error')) {
      return c.html(<V.Message ctx={ctx()} title="Sign-in cancelled"><p><a href="/login">Sign in again</a>.</p></V.Message>, 400);
    }
    let result;
    try {
      const url = new URL(c.req.url);
      result = await oidc.finish(`/callback${url.search}`, login);
    } catch (error) {
      console.error(`Login failed: ${(error as Error).message}`);
      return c.html(<V.Message ctx={ctx()} title="Sign-in failed"><p>Please <a href="/login">try again</a>.</p></V.Message>, 400);
    }
    // A new session (a new cookie value) at every login
    const old = getCookie(c, SESSION_COOKIE);
    if (old) db.deleteSession(hash(old));
    const token = randomBytes(32).toString('base64url');
    const t = now();
    db.insertSession({
      id: hash(token), email: result.email, sub: result.sub, sid: result.sid, email_verified: result.emailVerified ? 1 : 0,
      has_mfa: result.hasMfa ? 1 : 0, auth_at: result.authAt, id_token: result.idToken, refresh_token: result.refreshToken,
      created_at: t, last_seen: t, checked_at: t,
    });
    setCookie(c, SESSION_COOKIE, token, { domain: cfg.labDomain, path: '/', httpOnly: true, secure: true, sameSite: 'Lax', maxAge: cfg.sessionMax });
    if (login.step_up && !result.hasMfa && !cfg.insecureDisable2fa) return c.redirect(portal(`/mfa?rd=${encodeURIComponent(login.rd)}&retried=1`), 302);
    return c.redirect(login.rd, 302);
  });

  app.post('/logout', async (c) => {
    const token = getCookie(c, SESSION_COOKIE);
    const row = token ? db.getSession(hash(token)) : undefined;
    if (token) db.deleteSession(hash(token));
    deleteCookie(c, SESSION_COOKIE, { domain: cfg.labDomain, path: '/', secure: true });
    if (!row) return c.redirect('/signed-out', 302);
    return c.redirect(oidc.endSessionUrl(row.id_token, portal('/signed-out')), 302);
  });

  app.get('/signed-out', (c) =>
    c.html(<V.Message ctx={ctx()} title="Signed out"><p>You're signed out of all lab services. <a href="/login">Sign in again</a>.</p></V.Message>),
  );

  // The provider reports a sign-out (back-channel logout): end the matching sessions here too
  app.post('/backchannel-logout', async (c) => {
    const body = await c.req.parseBody();
    try {
      const { sid, sub } = await oidc.verifyLogoutToken(String(body.logout_token ?? ''));
      if (sid) db.deleteSessionsBy('sid', sid);
      else if (sub) db.deleteSessionsBy('sub', sub);
      return c.body(null, 200);
    } catch (error) {
      console.error(`Back-channel logout refused: ${(error as Error).message}`);
      return c.json({ error: 'invalid_request' }, 400);
    }
  });

  // ---- The overview
  app.get('/', async (c) => {
    const s = await session(c);
    if (!s) return c.html(<V.Welcome ctx={ctx()} />);
    if (!s.email_verified && !cfg.insecureDisableEmailVerification)
      return c.html(<V.Message ctx={ctx(s)} title="Email address not verified"><p>Verify your email address in your <a href={cfg.accountUrl}>account</a>, then sign in again.</p></V.Message>);
    if (!isLabMember(s.email, membership)) return c.html(<V.NotMember ctx={ctx(s)} pending={db.pendingRequestOf(s.email)} />);
    const admin = settings.isAdmin(s.email);
    const visible = settings.services.filter((sv) => sv.show && (sv.access !== 'admins' || admin));
    return c.html(<V.Home ctx={ctx(s)} services={visible} hasMfa={!!s.has_mfa} />);
  });

  // Why a service refused: not a member (request membership), admins only, or an unverified address
  app.get('/access', async (c) => {
    const s = await session(c);
    if (!s) return c.redirect(loginUrl(portal('/')), 302);
    const service = settings.services.find((sv) => sv.id === c.req.query('service'));
    const name = service?.name ?? 'This service';
    if (!s.email_verified && !cfg.insecureDisableEmailVerification)
      return c.html(<V.Message ctx={ctx(s)} title="Email address not verified"><p>Verify your email address in your <a href={cfg.accountUrl}>account</a>, then sign in again.</p></V.Message>, 403);
    if (!isLabMember(s.email, membership)) return c.html(<V.NotMember ctx={ctx(s)} pending={db.pendingRequestOf(s.email)} serviceName={name} />, 403);
    return c.html(<V.Message ctx={ctx(s)} title="No access"><p>{name} is only for lab admins.</p></V.Message>, 403);
  });

  app.get('/mfa', async (c) => {
    const s = await session(c);
    const rd = safeReturnUrl(c.req.query('rd'), cfg.labDomain);
    const service = settings.serviceForHost(new URL(rd).hostname);
    return c.html(<V.NeedsMfa ctx={ctx(s)} serviceName={service?.name ?? 'This service'} retryUrl={loginUrl(rd, true)} afterRetry={c.req.query('retried') === '1'} />);
  });

  // ---- Membership requests
  app.post('/request', async (c) => {
    const s = await session(c);
    if (!s) return c.redirect(loginUrl(portal('/')), 302);
    if (!s.email_verified && !cfg.insecureDisableEmailVerification) return c.redirect('/', 302);
    if (isLabMember(s.email, membership) || db.pendingRequestOf(s.email)) return c.redirect('/', 302);
    const body = await c.req.parseBody();
    const name = String(body.name ?? '').trim().slice(0, 200);
    const message = String(body.message ?? '').trim().slice(0, 2000);
    if (!name) return c.redirect('/', 302);
    db.addRequest(s.email, name, message);
    db.log(s.email, 'requested membership', s.email);
    await mail.requestReceived();
    return c.redirect('/', 302);
  });

  // ---- Admin
  async function admin(c: Context): Promise<SessionRow | Response> {
    const s = await session(c);
    if (!s) return c.redirect(loginUrl(portal('/admin'), true), 302);
    if (!settings.isAdmin(s.email) || (!s.email_verified && !cfg.insecureDisableEmailVerification))
      return c.html(<V.Message ctx={ctx(s)} title="No access"><p>The admin page is only for lab admins.</p></V.Message>, 403);
    return s;
  }
  async function adminChange(c: Context): Promise<SessionRow | Response> {
    const s = await admin(c);
    if (s instanceof Response) return s;
    if (!recentStepUp(s)) return c.redirect(loginUrl(portal('/admin'), true), 302);
    return s;
  }

  app.get('/admin', async (c) => {
    const s = await admin(c);
    if (s instanceof Response) return s;
    return c.html(
      <V.Admin ctx={ctx(s)} requests={db.pendingRequests()} members={db.members()} fixedMembers={settings.groups.lab} admins={settings.groups.admin}
        log={db.recentLog()} mailEnabled={mail.enabled} recent={recentStepUp(s)} stepUpUrl={loginUrl(portal('/admin'), true)} />,
    );
  });

  app.post('/admin/requests/:id/:decision', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const request = db.getRequest(Number(c.req.param('id')));
    const decision = c.req.param('decision');
    if (!request || request.status !== 'pending' || !['approve', 'reject'].includes(decision)) return c.redirect('/admin', 302);
    if (decision === 'approve') {
      db.addMember(request.email, request.name, s.email);
      db.decideRequest(request.id, 'approved', s.email);
      db.log(s.email, 'approved', request.email);
      await mail.welcome(request.email, request.name);
    } else {
      db.decideRequest(request.id, 'rejected', s.email);
      db.log(s.email, 'rejected', request.email);
    }
    return c.redirect('/admin', 302);
  });

  app.post('/admin/members', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const body = await c.req.parseBody();
    const email = String(body.email ?? '').trim().toLowerCase();
    const name = String(body.name ?? '').trim().slice(0, 200);
    if (!EMAIL.test(email) || !name) return c.redirect('/admin', 302);
    const pending = db.pendingRequestOf(email);
    if (pending) db.decideRequest(pending.id, 'approved', s.email);
    db.addMember(email, name, s.email);
    db.log(s.email, 'added', email);
    await mail.welcome(email, name);
    return c.redirect('/admin', 302);
  });

  app.post('/admin/members/remove', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const email = String((await c.req.parseBody()).email ?? '').trim().toLowerCase();
    if (db.removeMember(email)) {
      db.deleteSessionsOf(email); // takes effect immediately
      db.log(s.email, 'removed', email);
    }
    return c.redirect('/admin', 302);
  });

  app.notFound((c) => c.html(<V.Message ctx={ctx()} title="Not found"><p><a href="/">To the lab services</a>.</p></V.Message>, 404));
  return app;
}
