/** @jsxImportSource hono/jsx */
// The portal's pages: plain HTML and one stylesheet, in the look of the lab's login pages.
import type { Child } from 'hono/jsx';
import type { Service } from './settings.js';
import type { Admin as AdminEntry } from './settings.js';
import type { InvitationRow, LogRow, MemberRow, RequestRow } from './db.js';

export type Ctx = {
  labName: string;
  accountUrl: string;
  registrationOpen: boolean;
  email?: string;
  /** The account ID (sub): shown so admins can be listed in admins.yml */
  accountId?: string;
  isAdmin?: boolean;
};

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
        {ctx.accountId && (
          <footer class="muted">
            Account ID: <code>{ctx.accountId}</code>
          </footer>
        )}
      </body>
    </html>
  );
}

export function Welcome(props: { ctx: Ctx }) {
  return (
    <Layout ctx={props.ctx} title="Welcome">
      <section class="card center">
        <h1>Lab services</h1>
        <p>Sign in to use the lab's services, with the same account as for the lab's other tools (such as AmCAT and AnnoTinder).</p>
        <p>
          <a class="button" href="/login">
            Sign in
          </a>
        </p>
        <p class="muted">
          {props.ctx.registrationOpen
            ? 'No account yet? Create one on the sign-in page, then request lab membership here.'
            : 'No account yet? Ask a lab admin for an invitation.'}
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

export function NotMember(props: { ctx: Ctx; verified: boolean; pending?: RequestRow; rejected?: RequestRow; serviceName?: string }) {
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
        ) : props.rejected ? (
          <p>Your request of {date(props.rejected.created_at)} was not approved. Questions? Contact a lab admin.</p>
        ) : !props.verified ? (
          <p>
            You're signed in, but not a lab member. To request membership, first verify your email address in your{' '}
            <a href={props.ctx.accountUrl}>account</a>, then sign out and in again.
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

export const ADMIN_NOTES = ['invited', 'added', 'already-member', 'invalid', 'batch'] as const;
export type AdminNote = (typeof ADMIN_NOTES)[number];

/** The result of a batch invitation */
export type BatchResult = { invited: number; added: number; already: number; invalid: number; invalidLines: string[] };

function noteText(note: AdminNote, email = ''): string {
  return {
    invited: `Invitation sent to ${email}: they become a member at their first sign-in with that address.`,
    added: `${email} had already signed in with that address, and is now a member.`,
    'already-member': `${email} is already a member.`,
    invalid: 'Give an email address and a name (a list: at most 1000 lines).',
    batch: '',
  }[note];
}

export function Admin(props: {
  ctx: Ctx;
  requests: RequestRow[];
  invitations: InvitationRow[];
  members: MemberRow[];
  admins: (AdminEntry & { email?: string })[];
  log: LogRow[];
  mailEnabled: boolean;
  recent: boolean;
  stepUpUrl: string;
  note?: AdminNote;
  noteEmail?: string;
  batch?: BatchResult;
}) {
  const off = !props.recent;
  return (
    <Layout ctx={props.ctx} title="Admin">
      <h1>Lab membership</h1>
      {off && (
        <div class="banner">
          Changes need a recent login with a second factor. <a href={props.stepUpUrl}>Sign in again</a> first.
        </div>
      )}
      {props.note && props.note !== 'batch' && <div class="note">{noteText(props.note, props.noteEmail)}</div>}
      {props.batch && (
        <div class="note">
          Invited: {props.batch.invited} (members at their first sign-in). Members at once (they had already signed in):{' '}
          {props.batch.added}. Already members: {props.batch.already}. Lines that are not an email address: {props.batch.invalid}
          {props.batch.invalidLines.length > 0 && (
            <ul>
              {props.batch.invalidLines.map((l) => (
                <li>
                  <code>{l}</code>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {!props.mailEnabled && <p class="muted">Email is not set up: new requests only show here, and invitations are not sent.</p>}

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
                <button disabled={off}>Approve</button>
              </form>
              <form method="post" action={`/admin/requests/${r.id}/reject`}>
                <button class="secondary" disabled={off}>
                  Reject
                </button>
              </form>
            </td>
          </tr>
        ))}
      </table>

      <h2>Invite</h2>
      <p class="muted">
        Someone who signs in with this address (verified) becomes a member. They get an email; if they have no account yet,
        they create one with this address.
      </p>
      <form method="post" action="/admin/invitations" class="inline">
        <input name="email" type="email" placeholder="Email address" required />
        <input name="name" placeholder="Name" required maxlength={200} />
        <button disabled={off}>Invite</button>
      </form>
      <details class="batch">
        <summary>Invite several people at once</summary>
        <form method="post" action="/admin/invitations/batch" class="stack">
          <label>
            One per line: an email address, optionally followed by a comma and a name
            <textarea name="list" rows={6} placeholder={'jane@example.org, Jane Doe\njohn@example.org'}></textarea>
          </label>
          <label class="check">
            <input type="checkbox" name="send_email" /> Send each of them an email (an invitation, or a welcome for those who
            become members at once)
          </label>
          <button disabled={off}>Invite</button>
        </form>
      </details>
      {props.invitations.length > 0 && (
        <table>
          {props.invitations.map((i) => (
            <tr>
              <td>
                <strong>{i.name}</strong>
                <br />
                {i.email}
              </td>
              <td class="muted">
                Invited by {i.added_by}, {date(i.added_at)}; not signed in yet
              </td>
              <td class="actions">
                <form method="post" action="/admin/invitations/remove">
                  <input type="hidden" name="email" value={i.email} />
                  <button class="secondary" disabled={off}>
                    Withdraw
                  </button>
                </form>
              </td>
            </tr>
          ))}
        </table>
      )}

      <h2>Members</h2>
      {props.members.length === 0 && <p class="muted">No members yet.</p>}
      <table>
        {props.members.map((m) => (
          <tr>
            <td>
              <strong>{m.name ?? m.email}</strong>
              <br />
              {m.email}
            </td>
            <td class="muted">
              Added by {m.added_by}, {date(m.added_at)}
              <br />
              Last sign-in {date(m.last_login)}
            </td>
            <td class="actions">
              <form method="post" action="/admin/members/remove">
                <input type="hidden" name="iss" value={m.iss} />
                <input type="hidden" name="sub" value={m.sub} />
                <button class="secondary" disabled={off}>
                  Remove
                </button>
              </form>
            </td>
          </tr>
        ))}
      </table>
      <p class="muted">
        Admins (in admins.yml on the server):{' '}
        {props.admins.map((a, i) => (
          <>
            {i > 0 && ', '}
            {a.name}
            {a.email ? ` (${a.email})` : ' (not signed in yet)'}
          </>
        ))}
        .
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
