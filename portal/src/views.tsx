/** @jsxImportSource hono/jsx */
// The portal's pages: plain HTML and one stylesheet, in the look of the lab's login pages.
import type { Child } from 'hono/jsx';
import type { Service } from './settings.js';
import type { MemberRow, RequestRow } from './db.js';

export type Ctx = { labName: string; accountUrl: string; registrationOpen: boolean; email?: string; isAdmin?: boolean };

const date = (t: number) => new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ');

export function Layout(props: { ctx: Ctx; title: string; children: Child }) {
  const { ctx } = props;
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`${props.title} · ${ctx.labName}`}</title>
        <link rel="icon" href="/static/logo.svg" />
        <link rel="stylesheet" href="/static/style.css" />
      </head>
      <body>
        <header class="top">
          <a class="brand" href="/">
            <img src="/static/logo.svg" alt="" />
            <span>
              <span class="name">{ctx.labName}</span>
              <span class="sub">Lab services</span>
            </span>
          </a>
          {ctx.email && (
            <nav>
              <span class="who">{ctx.email}</span>
              {ctx.isAdmin && <a href="/admin">Admin</a>}
              <a href={ctx.accountUrl}>Account</a>
              <form method="post" action="/logout">
                <button class="link">Sign out</button>
              </form>
            </nav>
          )}
        </header>
        <main>{props.children}</main>
      </body>
    </html>
  );
}

export function Welcome(props: { ctx: Ctx }) {
  return (
    <Layout ctx={props.ctx} title="Welcome">
      <section class="card center">
        <h1>Lab services</h1>
        <p>Sign in with your lab account to use the lab's services.</p>
        <p>
          <a class="button" href="/login">
            Sign in
          </a>
        </p>
        <p class="muted">
          {props.ctx.registrationOpen
            ? 'No account yet? Choose "Register" on the sign-in page, then request lab membership here.'
            : 'No account yet? Ask a lab admin.'}
        </p>
      </section>
    </Layout>
  );
}

export function Home(props: { ctx: Ctx; services: Service[]; hasMfa: boolean }) {
  return (
    <Layout ctx={props.ctx} title="Lab services">
      {!props.hasMfa && (
        <div class="banner">
          <strong>Protect your account with a second factor.</strong> Add an authenticator app or a passkey in your{' '}
          <a href={props.ctx.accountUrl}>account</a> (Account security, Signing in). Some services require it.
        </div>
      )}
      <h1>Lab services</h1>
      {props.services.length === 0 && <p class="muted">No services yet.</p>}
      <ul class="services">
        {props.services.map((s) => (
          <li>
            <a href={`https://${s.host}/`}>
              <strong>{s.name}</strong>
              {s.description && <span>{s.description}</span>}
              {s.mfa === 'required' && s.access !== 'public' && <em>Second factor required</em>}
            </a>
          </li>
        ))}
      </ul>
    </Layout>
  );
}

export function NotMember(props: { ctx: Ctx; pending?: RequestRow; serviceName?: string }) {
  return (
    <Layout ctx={props.ctx} title="Lab membership">
      <section class="card">
        <h1>Lab membership</h1>
        {props.serviceName && <p>{props.serviceName} is only for lab members.</p>}
        {props.pending ? (
          <p>
            Your request of {date(props.pending.created_at)} is waiting for a lab admin. You'll get an email when it's
            approved.
          </p>
        ) : (
          <>
            <p>You're signed in, but not a lab member yet. Request membership, and a lab admin will look at it.</p>
            <form method="post" action="/request" class="stack">
              <label>
                Your name
                <input name="name" required maxlength={200} />
              </label>
              <label>
                Who are you, and what do you need? (e.g. your project or supervisor)
                <textarea name="message" rows={4} maxlength={2000}></textarea>
              </label>
              <button>Request membership</button>
            </form>
          </>
        )}
      </section>
    </Layout>
  );
}

export function Message(props: { ctx: Ctx; title: string; children: Child }) {
  return (
    <Layout ctx={props.ctx} title={props.title}>
      <section class="card">
        <h1>{props.title}</h1>
        {props.children}
      </section>
    </Layout>
  );
}

export function NeedsMfa(props: { ctx: Ctx; serviceName: string; retryUrl: string; afterRetry: boolean }) {
  return (
    <Message ctx={props.ctx} title="Second factor required">
      <p>{props.serviceName} requires a login with a second factor (an authenticator app or a passkey).</p>
      {props.afterRetry ? (
        <p>
          Your account has no second factor yet. Add one in your <a href={props.ctx.accountUrl}>account</a> (Account
          security, Signing in), then <a href={props.retryUrl}>sign in again</a>.
        </p>
      ) : (
        <p>
          <a class="button" href={props.retryUrl}>
            Sign in with your second factor
          </a>
        </p>
      )}
    </Message>
  );
}

export function Admin(props: {
  ctx: Ctx;
  requests: RequestRow[];
  members: MemberRow[];
  fixedMembers: string[];
  admins: string[];
  log: { at: number; actor: string; action: string; subject: string }[];
  mailEnabled: boolean;
  recent: boolean;
  stepUpUrl: string;
}) {
  return (
    <Layout ctx={props.ctx} title="Admin">
      <h1>Lab membership</h1>
      {!props.recent && (
        <div class="banner">
          Changes need a recent login with a second factor. <a href={props.stepUpUrl}>Sign in again</a> first.
        </div>
      )}
      {!props.mailEnabled && <p class="muted">Email is not set up: new requests only show here.</p>}

      <h2>Requests</h2>
      {props.requests.length === 0 && <p class="muted">No pending requests.</p>}
      <table>
        {props.requests.map((r) => (
          <tr>
            <td>
              <strong>{r.name}</strong>
              <br />
              {r.email}
              <br />
              <span class="muted">{date(r.created_at)}</span>
            </td>
            <td class="message">{r.message}</td>
            <td class="actions">
              <form method="post" action={`/admin/requests/${r.id}/approve`}>
                <button disabled={!props.recent}>Approve</button>
              </form>
              <form method="post" action={`/admin/requests/${r.id}/reject`}>
                <button class="secondary" disabled={!props.recent}>
                  Reject
                </button>
              </form>
            </td>
          </tr>
        ))}
      </table>

      <h2>Add a member</h2>
      <form method="post" action="/admin/members" class="inline">
        <input name="email" type="email" placeholder="Email address" required />
        <input name="name" placeholder="Name" required maxlength={200} />
        <button disabled={!props.recent}>Add</button>
      </form>

      <h2>Members</h2>
      <table>
        {props.members.map((m) => (
          <tr>
            <td>
              <strong>{m.name}</strong>
              <br />
              {m.email}
            </td>
            <td class="muted">
              Added by {m.added_by}, {date(m.added_at)}
            </td>
            <td class="actions">
              <form method="post" action="/admin/members/remove">
                <input type="hidden" name="email" value={m.email} />
                <button class="secondary" disabled={!props.recent}>
                  Remove
                </button>
              </form>
            </td>
          </tr>
        ))}
      </table>
      <p class="muted">
        Fixed in groups.yml (changed on the server): admins {props.admins.join(', ')}
        {props.fixedMembers.length ? `; members ${props.fixedMembers.join(', ')}` : ''}.
      </p>

      <h2>Log</h2>
      <table class="log">
        {props.log.map((l) => (
          <tr>
            <td class="muted">{date(l.at)}</td>
            <td>{l.actor}</td>
            <td>{l.action}</td>
            <td>{l.subject}</td>
          </tr>
        ))}
      </table>
    </Layout>
  );
}
