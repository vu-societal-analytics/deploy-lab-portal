/** @jsxImportSource hono/jsx */
// The portal's routes: the login, the authorization endpoint for Caddy (/auth), the overview of the services,
// membership (requests and invitations), and the admin page.
import { Hono, type Context } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { csrf } from 'hono/csrf';
import { secureHeaders } from 'hono/secure-headers';
import { createHash, randomBytes } from 'node:crypto';
import type { Config } from './config.js';
import type { Db, Id, SessionRow } from './db.js';
import type { SessionLimits, Settings } from './settings.js';
import type { Oidc } from './oidc.js';
import type { Mail } from './mail.js';
import { decide, isLabMember, safeReturnUrl, sessionValid, stepUpValid, type Membership, type Person } from './authz.js';
import * as V from './views.js';
import { MAX_INVITEES, parseInviteeList } from './batch.js';

const SESSION_COOKIE = 'lab_session';
const LOGIN_COOKIE = 'lab_login';
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** After a rejected request, the next one can be made after this long */
const REQUEST_AGAIN_AFTER = 7 * 24 * 3600;

const hash = (token: string) => createHash('sha256').update(token).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
const idOf = (s: Id): Id => ({ iss: s.iss, sub: s.sub });

/** The issuer of sign-ins in development mode (no OIDC provider) */
export const DEV_ISSUER = 'dev';

/** oidc is missing in development mode; issuer is the provider's (or DEV_ISSUER) */
export type Deps = { cfg: Config; db: Db; settings: Settings; oidc?: Oidc; issuer: string; mail: Mail };

export function createApp({ cfg, db, settings, oidc, issuer, mail }: Deps) {
  const app = new Hono();
  const membership: Membership = {
    isAdmin: (p) => p.iss === issuer && settings.isAdmin(p.sub),
    isMember: (p) => db.isMember(p),
  };
  const rules = { insecureDisable2fa: cfg.insecureDisable2fa };
  const portal = (path: string) => `${cfg.portalUrl}${path}`;
  // Development mode runs on http://localhost: cookies without Secure and without a domain
  const secure = !cfg.devMode;
  const cookieDomain = cfg.devMode ? undefined : cfg.labDomain;
  /** Where to return after a login: only addresses in the lab zone (in development mode: on the portal itself) */
  const returnUrl = (raw: string | undefined) =>
    cfg.devMode ? (raw?.startsWith(`${cfg.portalUrl}/`) ? raw : portal('/')) : safeReturnUrl(raw, cfg.labDomain);

  const defaults = { idle: cfg.sessionIdle, max: cfg.sessionMax };
  /** The signed-in person, or null. The portal keeps its own sessions, independent of the provider's: they end
   *  after AUTH_SESSION_IDLE without use, after AUTH_SESSION_MAX, or on sign-out here. An app may have its own limits
   *  (services.yml): then the session counts for that app under those limits. */
  function session(c: Context, limits: SessionLimits = defaults): SessionRow | null {
    const token = getCookie(c, SESSION_COOKIE);
    if (!token) return null;
    const id = hash(token);
    const row = db.getSession(id);
    if (!row) return null;
    const t = now();
    if (!sessionValid(row, t, settings.longestSession(defaults))) {
      db.deleteSession(id); // expired for every app
      return null;
    }
    if (!sessionValid(row, t, limits)) return null; // expired for this app (sign in again)
    if (t - row.last_seen > 60) db.touchSession(id);
    return row;
  }

  const person = (s: SessionRow): Person => ({ iss: s.iss, sub: s.sub, hasMfa: !!s.has_mfa });
  const isAdmin = (s: SessionRow) => membership.isAdmin(person(s));
  const isMember = (s: SessionRow) => isLabMember(person(s), membership);
  /** Requests and invitations need an address the provider verified (otherwise anyone could claim one) */
  const verified = (s: { email_verified: number }) => !!s.email_verified || cfg.insecureDisableEmailVerification;
  /** How an admin appears in the log: the name from admins.yml */
  const adminName = (s: SessionRow) => settings.admins.find((a) => a.sub === s.sub)?.name ?? s.email;
  const ctx = (s?: SessionRow | null): V.Ctx => ({
    labName: cfg.labName,
    accountUrl: cfg.accountUrl,
    registrationOpen: cfg.registrationOpen,
    email: s?.email,
    accountId: s?.sub,
    isAdmin: s ? isAdmin(s) : false,
  });
  /** Admin changes: a 2FA login of at most AUTH_STEP_UP_MAX_AGE ago, and at most AUTH_STEP_UP_IDLE since the
   *  login or the last admin change (each change renews it). */
  const recentStepUp = (s: SessionRow) =>
    stepUpValid(s, now(), { idle: cfg.stepUpIdle, max: cfg.stepUpMaxAge }, cfg.insecureDisable2fa);
  const loginUrl = (rd: string, stepUp = false) => portal(`/login?rd=${encodeURIComponent(rd)}${stepUp ? '&step_up=1' : ''}`);

  /** At sign-in: someone invited by email becomes a member when the provider verified that address. */
  function joinByInvitation(id: Id, email: string, emailVerified: boolean) {
    if (!emailVerified && !cfg.insecureDisableEmailVerification) return;
    const invitation = db.getInvitation(email);
    if (!invitation) return;
    db.transaction(() => {
      if (!db.isMember(id)) {
        db.addMember(id, invitation.added_by);
        db.setUserName(id, invitation.name);
        db.settleRequestsOf(id, invitation.added_by);
        db.log(invitation.added_by, 'invited, joined', email);
      }
      db.removeInvitation(email);
    });
  }

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
    app.use(path, secureHeaders({ contentSecurityPolicy: { defaultSrc: ["'self'"], formAction: cfg.oidcHost ? ["'self'", new URL(cfg.oidcHost).origin] : ["'self'"], frameAncestors: ["'none'"] } }));
  for (const path of ['/login', '/logout', '/request', '/admin/*']) app.use(path, csrf({ origin: cfg.portalUrl }));

  app.get('/health', (c) => c.text('ok'));

  // ---- Authorization endpoint for Caddy (forward_auth): only reachable from Caddy, not through the portal's site
  app.get('/auth', (c) => {
    const host = (c.req.header('X-Forwarded-Host') ?? '').toLowerCase();
    const uri = c.req.header('X-Forwarded-Uri') ?? '/';
    const service = settings.serviceForHost(host);
    if (!service) return c.text('Unknown service', 403);
    const original = `https://${host}${uri.startsWith('/') ? uri : '/'}`;
    const s = session(c, { idle: service.sessionIdle ?? cfg.sessionIdle, max: service.sessionMax ?? cfg.sessionMax });
    const decision = decide(service, s ? person(s) : null, membership, rules);
    switch (decision.result) {
      case 'allow':
        if (s) {
          c.header('X-Auth-Request-User', s.sub);
          c.header('X-Auth-Request-Email', s.email);
        }
        return c.body(null, 200);
      case 'login':
        return c.redirect(loginUrl(original), 302);
      case 'mfa':
        return c.redirect(portal(`/mfa?rd=${encodeURIComponent(original)}`), 302);
      default:
        return c.redirect(portal(`/access?service=${encodeURIComponent(service.id)}`), 302);
    }
  });

  // ---- Login
  app.get('/login', async (c) => {
    const rd = returnUrl(c.req.query('rd') ?? portal('/'));
    const stepUp = c.req.query('step_up') === '1';
    if (!oidc) return c.html(<V.DevLogin ctx={ctx()} rd={rd} stepUp={stepUp} />);
    const start = await oidc.start(stepUp ? 0 : undefined);
    db.insertLogin({ state: start.state, nonce: start.nonce, verifier: start.verifier, rd, step_up: stepUp ? 1 : 0, created_at: now() });
    setCookie(c, LOGIN_COOKIE, start.state, { path: '/callback', httpOnly: true, secure, sameSite: 'Lax', maxAge: 900 });
    return c.redirect(start.url, 302);
  });

  app.get('/callback', async (c) => {
    const state = c.req.query('state') ?? '';
    const cookieState = getCookie(c, LOGIN_COOKIE);
    deleteCookie(c, LOGIN_COOKIE, { path: '/callback', secure });
    const login = state && cookieState === state ? db.takeLogin(state) : undefined;
    if (!login) return c.html(<V.Message ctx={ctx()} title="Sign-in expired"><p><a href="/login">Sign in again</a>.</p></V.Message>, 400);
    if (c.req.query('error')) {
      return c.html(<V.Message ctx={ctx()} title="Sign-in cancelled"><p><a href="/login">Sign in again</a>.</p></V.Message>, 400);
    }
    if (!oidc) return c.redirect('/', 302);
    let result;
    try {
      const url = new URL(c.req.url);
      result = await oidc.finish(`/callback${url.search}`, login);
    } catch (error) {
      console.error(`Login failed: ${(error as Error).message}`);
      return c.html(<V.Message ctx={ctx()} title="Sign-in failed"><p>Please <a href="/login">try again</a>.</p></V.Message>, 400);
    }
    return signIn(c, result, login.rd, !!login.step_up);
  });

  // Development mode: sign in as anyone, without a provider (the form of GET /login)
  app.post('/login', async (c) => {
    if (oidc) return c.notFound();
    const body = await c.req.parseBody();
    const email = String(body.email ?? '').trim().toLowerCase();
    if (!EMAIL.test(email)) return c.redirect('/login', 302);
    const t = now();
    const mfa = body.mfa === 'on';
    return signIn(
      c,
      { iss: DEV_ISSUER, sub: email, email, emailVerified: true, hasMfa: mfa, authAt: t, idToken: '' },
      returnUrl(String(body.rd ?? '')),
      body.step_up === '1',
    );
  });

  /** A new session after a login (with the provider, or in development mode) */
  function signIn(
    c: Context,
    result: { iss: string; sub: string; email: string; emailVerified: boolean; hasMfa: boolean; authAt: number; idToken: string },
    rd: string,
    stepUp: boolean,
  ) {
    const id = { iss: result.iss, sub: result.sub };
    db.upsertUser(id, result.email, result.emailVerified);
    joinByInvitation(id, result.email, result.emailVerified);
    // A new session (a new cookie value) at every login
    const old = getCookie(c, SESSION_COOKIE);
    if (old) db.deleteSession(hash(old));
    const token = randomBytes(32).toString('base64url');
    const t = now();
    db.insertSession({
      id: hash(token), ...id, email: result.email, email_verified: result.emailVerified ? 1 : 0,
      has_mfa: result.hasMfa ? 1 : 0, auth_at: result.authAt, step_up_at: t, id_token: result.idToken, created_at: t, last_seen: t,
    });
    setCookie(c, SESSION_COOKIE, token, { domain: cookieDomain, path: '/', httpOnly: true, secure, sameSite: 'Lax', maxAge: settings.longestSession(defaults).max });
    if (stepUp && !result.hasMfa && !cfg.insecureDisable2fa) return c.redirect(portal(`/mfa?rd=${encodeURIComponent(rd)}&retried=1`), 302);
    return c.redirect(rd, 302);
  }

  app.post('/logout', (c) => {
    const token = getCookie(c, SESSION_COOKIE);
    const row = token ? db.getSession(hash(token)) : undefined;
    if (token) db.deleteSession(hash(token));
    deleteCookie(c, SESSION_COOKIE, { domain: cookieDomain, path: '/', secure });
    if (!row || !oidc) return c.redirect('/signed-out', 302);
    return c.redirect(oidc.endSessionUrl(row.id_token, portal('/signed-out')), 302);
  });

  app.get('/signed-out', (c) =>
    c.html(<V.Message ctx={ctx()} title="Signed out"><p>You're signed out of all lab services. <a href="/login">Sign in again</a>.</p></V.Message>),
  );

  // ---- The overview
  const notMember = (s: SessionRow, serviceName?: string) => {
    const last = db.lastRequestOf(idOf(s));
    return (
      <V.NotMember
        ctx={ctx(s)}
        verified={verified(s)}
        pending={last?.status === 'pending' ? last : undefined}
        rejected={last?.status === 'rejected' && now() - (last.decided_at ?? 0) < REQUEST_AGAIN_AFTER ? last : undefined}
        serviceName={serviceName}
      />
    );
  };

  app.get('/', (c) => {
    const s = session(c);
    if (!s) return c.html(<V.Welcome ctx={ctx()} />);
    if (!isMember(s)) return c.html(notMember(s));
    const admin = isAdmin(s);
    const visible = settings.services.filter((sv) => sv.show && (sv.access !== 'admins' || admin));
    return c.html(<V.Home ctx={ctx(s)} services={visible} hasMfa={!!s.has_mfa} />);
  });

  // Why a service refused: not a member (request membership), or admins only
  app.get('/access', (c) => {
    const s = session(c);
    if (!s) return c.redirect(loginUrl(portal('/')), 302);
    const name = settings.services.find((sv) => sv.id === c.req.query('service'))?.name ?? 'This service';
    if (!isMember(s)) return c.html(notMember(s, name), 403);
    return c.html(<V.Message ctx={ctx(s)} title="No access"><p>{name} is only for lab admins.</p></V.Message>, 403);
  });

  app.get('/mfa', (c) => {
    const s = session(c);
    const rd = returnUrl(c.req.query('rd'));
    const service = settings.serviceForHost(new URL(rd).hostname);
    return c.html(<V.NeedsMfa ctx={ctx(s)} serviceName={service?.name ?? 'This service'} retryUrl={loginUrl(rd, true)} afterRetry={c.req.query('retried') === '1'} />);
  });

  // ---- Membership requests
  app.post('/request', async (c) => {
    const s = session(c);
    if (!s) return c.redirect(loginUrl(portal('/')), 302);
    const id = idOf(s);
    const last = db.lastRequestOf(id);
    const blocked =
      !verified(s) ||
      isMember(s) ||
      last?.status === 'pending' ||
      (last?.status === 'rejected' && now() - (last.decided_at ?? 0) < REQUEST_AGAIN_AFTER);
    if (blocked) return c.redirect('/', 302);
    const body = await c.req.parseBody();
    const name = String(body.name ?? '').trim().slice(0, 200);
    const message = String(body.message ?? '').trim().slice(0, 2000);
    if (!name) return c.redirect('/', 302);
    db.transaction(() => {
      db.setUserName(id, name, true);
      db.addRequest(id, name, message);
      db.log(s.email, 'requested membership', s.email);
    });
    await mail.requestReceived();
    return c.redirect('/', 302);
  });

  // ---- Admin
  async function admin(c: Context): Promise<SessionRow | Response> {
    const s = session(c);
    if (!s) return c.redirect(loginUrl(portal('/admin'), true), 302);
    if (!isAdmin(s)) return c.html(<V.Message ctx={ctx(s)} title="No access"><p>The admin page is only for lab admins.</p></V.Message>, 403);
    return s;
  }
  async function adminChange(c: Context): Promise<SessionRow | Response> {
    const s = await admin(c);
    if (s instanceof Response) return s;
    if (!recentStepUp(s)) return c.redirect(loginUrl(portal('/admin'), true), 302);
    db.touchStepUp(s.id);
    return s;
  }
  const done = (c: Context, note: V.AdminNote, email = '') =>
    c.redirect(`/admin?note=${note}${email ? `&email=${encodeURIComponent(email)}` : ''}`, 302);

  /** The summary of a batch invitation, from the redirect after it */
  const batchResult = (c: Context): V.BatchResult | undefined => {
    if (c.req.query('note') !== 'batch') return undefined;
    const [invited, added, already, invalid] = (c.req.query('counts') ?? '').split(',').map((n) => Number(n) || 0);
    const lines = (c.req.query('invalid') ?? '').split('\n').filter(Boolean);
    return { invited, added, already, invalid, invalidLines: lines };
  };

  app.get('/admin', async (c) => {
    const s = await admin(c);
    if (s instanceof Response) return s;
    const admins = settings.admins.map((a) => ({ ...a, email: db.getUser({ iss: issuer, sub: a.sub })?.email }));
    const note = V.ADMIN_NOTES.includes(c.req.query('note') as V.AdminNote) ? (c.req.query('note') as V.AdminNote) : undefined;
    return c.html(
      <V.Admin ctx={ctx(s)} requests={db.pendingRequests()} invitations={db.invitations()} members={db.members()} admins={admins}
        log={db.recentLog()} mailEnabled={mail.enabled} recent={recentStepUp(s)} stepUpUrl={loginUrl(portal('/admin'), true)}
        note={note} noteEmail={c.req.query('email')} batch={batchResult(c)} />,
    );
  });

  app.post('/admin/requests/:id/:decision', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const request = db.getRequest(Number(c.req.param('id')));
    const decision = c.req.param('decision');
    if (!request || request.status !== 'pending' || !['approve', 'reject'].includes(decision)) return c.redirect('/admin', 302);
    const by = adminName(s);
    if (decision === 'approve') {
      db.transaction(() => {
        db.addMember(idOf(request), by);
        db.decideRequest(request.id, 'approved', by);
        db.log(by, 'approved', request.email);
      });
      await mail.welcome(request.email, request.name);
    } else {
      db.decideRequest(request.id, 'rejected', by);
      db.log(by, 'rejected', request.email);
    }
    return c.redirect('/admin', 302);
  });

  /** Invites one person by email address: someone who already signed in with that verified address becomes a
   *  member now; otherwise the invitation waits for their first sign-in. Emails only when sendEmail. */
  async function invite(email: string, name: string, by: string, sendEmail: boolean): Promise<'invited' | 'added' | 'already-member'> {
    if (db.memberByEmail(email)) return 'already-member';
    const user = db.userByVerifiedEmail(email);
    if (user) {
      db.transaction(() => {
        db.addMember(idOf(user), by);
        db.setUserName(idOf(user), name);
        db.settleRequestsOf(idOf(user), by);
        db.log(by, 'added', email);
      });
      if (sendEmail) await mail.welcome(email, name);
      return 'added';
    }
    db.addInvitation(email, name, by);
    db.log(by, 'invited', email);
    if (sendEmail) await mail.invitation(email, name);
    return 'invited';
  }

  app.post('/admin/invitations', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const body = await c.req.parseBody();
    const email = String(body.email ?? '').trim().toLowerCase();
    const name = String(body.name ?? '').trim().slice(0, 200);
    if (!EMAIL.test(email) || !name) return done(c, 'invalid');
    return done(c, await invite(email, name, adminName(s), true), email);
  });

  // Many at once: a pasted list, one per line ("email" or "email, name"); emails to them only when asked
  app.post('/admin/invitations/batch', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const body = await c.req.parseBody();
    const { invitees, invalid } = parseInviteeList(String(body.list ?? ''));
    if (invitees.length > MAX_INVITEES) return done(c, 'invalid');
    const sendEmail = body.send_email === 'on';
    const by = adminName(s);
    const counts = { invited: 0, added: 0, 'already-member': 0 };
    for (const p of invitees) counts[await invite(p.email, p.name, by, sendEmail)]++;
    const q = new URLSearchParams({
      note: 'batch',
      counts: [counts.invited, counts.added, counts['already-member'], invalid.length].join(','),
      invalid: invalid.slice(0, 10).join('\n'),
    });
    return c.redirect(`/admin?${q}`, 302);
  });

  app.post('/admin/invitations/remove', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const email = String((await c.req.parseBody()).email ?? '').trim().toLowerCase();
    if (db.removeInvitation(email)) db.log(adminName(s), 'withdrew invitation', email);
    return c.redirect('/admin', 302);
  });

  app.post('/admin/members/remove', async (c) => {
    const s = await adminChange(c);
    if (s instanceof Response) return s;
    const body = await c.req.parseBody();
    const id = { iss: String(body.iss ?? ''), sub: String(body.sub ?? '') };
    const user = db.getUser(id);
    if (user && db.removeMember(id)) {
      db.deleteSessionsOf(id); // takes effect immediately
      db.log(adminName(s), 'removed', user.email);
    }
    return c.redirect('/admin', 302);
  });

  app.notFound((c) => c.html(<V.Message ctx={ctx()} title="Not found"><p><a href="/">To the lab services</a>.</p></V.Message>, 404));
  return app;
}
