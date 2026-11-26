// The portal's own data, in one SQLite file in ./data: everything the portal itself changes.
//   users        everyone who signed in, by issuer + account ID (iss, sub), with their current email address
//   members      lab members (approved by an admin, or joined through an invitation)
//   invitations  email addresses an admin invited: the first sign-in with that verified address becomes a member
//   requests     membership requests
//   sessions     sign-ins (the cookie holds a random token; only its hash is stored), and logins in progress
//   log          who changed what
// A daily copy (without sessions) goes to ./backups, which the server's backup picks up.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readdirSync, renameSync, rmSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** A person, as the provider identifies them: the issuer and the account ID (sub) */
export type Id = { iss: string; sub: string };

export type UserRow = Id & { email: string; email_verified: number; name: string | null; first_login: number; last_login: number };

export type MemberRow = Id & { email: string; name: string | null; last_login: number; added_by: string; added_at: number };

export type InvitationRow = { email: string; name: string; added_by: string; added_at: number };

export type RequestRow = Id & {
  id: number;
  email: string;
  name: string;
  message: string;
  status: 'pending' | 'approved' | 'rejected';
  created_at: number;
  decided_by: string | null;
  decided_at: number | null;
};

export type SessionRow = Id & {
  id: string;
  email: string;
  email_verified: number;
  has_mfa: number;
  auth_at: number;
  id_token: string;
  created_at: number;
  last_seen: number;
};

export type LoginRow = { state: string; nonce: string; verifier: string; rd: string; step_up: number; created_at: number };

export type LogRow = { at: number; actor: string; action: string; subject: string };

const SCHEMA_VERSION = 2;
const now = () => Math.floor(Date.now() / 1000);

export class Db {
  private db: DatabaseSync;

  constructor(file: string) {
    if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    const version = (this.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
    const empty = !this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table'`).get();
    if (!empty && version !== SCHEMA_VERSION)
      throw new Error(`${file} has database version ${version}, this portal needs ${SCHEMA_VERSION}: see the README (Updates)`);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS users (
        iss TEXT NOT NULL, sub TEXT NOT NULL, email TEXT NOT NULL, email_verified INTEGER NOT NULL, name TEXT,
        first_login INTEGER NOT NULL, last_login INTEGER NOT NULL, PRIMARY KEY (iss, sub));
      CREATE INDEX IF NOT EXISTS users_email ON users (email);
      CREATE TABLE IF NOT EXISTS members (
        iss TEXT NOT NULL, sub TEXT NOT NULL, added_by TEXT NOT NULL, added_at INTEGER NOT NULL,
        PRIMARY KEY (iss, sub), FOREIGN KEY (iss, sub) REFERENCES users (iss, sub));
      CREATE TABLE IF NOT EXISTS invitations (
        email TEXT PRIMARY KEY, name TEXT NOT NULL, added_by TEXT NOT NULL, added_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, iss TEXT NOT NULL, sub TEXT NOT NULL, name TEXT NOT NULL,
        message TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_by TEXT, decided_at INTEGER,
        FOREIGN KEY (iss, sub) REFERENCES users (iss, sub));
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, iss TEXT NOT NULL, sub TEXT NOT NULL, email TEXT NOT NULL,
        email_verified INTEGER NOT NULL, has_mfa INTEGER NOT NULL, auth_at INTEGER NOT NULL, id_token TEXT NOT NULL,
        created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS sessions_sub ON sessions (iss, sub);
      CREATE TABLE IF NOT EXISTS logins (
        state TEXT PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, rd TEXT NOT NULL,
        step_up INTEGER NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
        subject TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      PRAGMA user_version = ${SCHEMA_VERSION};
    `);
  }

  /** Runs fn in one transaction (all or nothing). */
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  // ---- Users: everyone who signed in (just in time, at every login)
  upsertUser(id: Id, email: string, emailVerified: boolean) {
    const t = now();
    this.db
      .prepare(
        `INSERT INTO users (iss, sub, email, email_verified, first_login, last_login) VALUES (?,?,?,?,?,?)
         ON CONFLICT (iss, sub) DO UPDATE SET email = excluded.email, email_verified = excluded.email_verified, last_login = excluded.last_login`,
      )
      .run(id.iss, id.sub, email, emailVerified ? 1 : 0, t, t);
  }
  getUser(id: Id): UserRow | undefined {
    return this.db.prepare(`SELECT * FROM users WHERE iss = ? AND sub = ?`).get(id.iss, id.sub) as UserRow | undefined;
  }
  /** The name, if none is known yet (from a request or an invitation) */
  setUserName(id: Id, name: string, overwrite = false) {
    this.db
      .prepare(`UPDATE users SET name = ? WHERE iss = ? AND sub = ?${overwrite ? '' : ' AND name IS NULL'}`)
      .run(name, id.iss, id.sub);
  }
  /** Someone who signed in with this address, verified by the provider */
  userByVerifiedEmail(email: string): UserRow | undefined {
    return this.db.prepare(`SELECT * FROM users WHERE email = ? AND email_verified = 1 ORDER BY last_login DESC LIMIT 1`).get(email) as
      | UserRow
      | undefined;
  }
  emailsOf(subs: string[], iss: string): string[] {
    if (!subs.length) return [];
    const rows = this.db
      .prepare(`SELECT email FROM users WHERE iss = ? AND sub IN (${subs.map(() => '?').join(',')})`)
      .all(iss, ...subs) as { email: string }[];
    return rows.map((r) => r.email);
  }

  // ---- Members
  isMember(id: Id): boolean {
    return !!this.db.prepare(`SELECT 1 FROM members WHERE iss = ? AND sub = ?`).get(id.iss, id.sub);
  }
  members(): MemberRow[] {
    return this.db
      .prepare(
        `SELECT m.iss, m.sub, u.email, u.name, u.last_login, m.added_by, m.added_at
         FROM members m JOIN users u USING (iss, sub) ORDER BY COALESCE(u.name, u.email)`,
      )
      .all() as MemberRow[];
  }
  memberByEmail(email: string): MemberRow | undefined {
    return this.members().find((m) => m.email === email);
  }
  addMember(id: Id, by: string) {
    this.db.prepare(`INSERT OR IGNORE INTO members VALUES (?,?,?,?)`).run(id.iss, id.sub, by, now());
  }
  removeMember(id: Id): boolean {
    return Number(this.db.prepare(`DELETE FROM members WHERE iss = ? AND sub = ?`).run(id.iss, id.sub).changes) > 0;
  }

  // ---- Invitations (by email address; used up at the first sign-in with that verified address)
  invitations(): InvitationRow[] {
    return this.db.prepare(`SELECT * FROM invitations ORDER BY added_at`).all() as InvitationRow[];
  }
  getInvitation(email: string): InvitationRow | undefined {
    return this.db.prepare(`SELECT * FROM invitations WHERE email = ?`).get(email) as InvitationRow | undefined;
  }
  addInvitation(email: string, name: string, by: string) {
    this.db.prepare(`INSERT OR REPLACE INTO invitations VALUES (?,?,?,?)`).run(email, name, by, now());
  }
  removeInvitation(email: string): boolean {
    return Number(this.db.prepare(`DELETE FROM invitations WHERE email = ?`).run(email).changes) > 0;
  }

  // ---- Membership requests
  private requestSelect = `SELECT r.*, u.email FROM requests r JOIN users u USING (iss, sub)`;
  /** The person's most recent request */
  lastRequestOf(id: Id): RequestRow | undefined {
    return this.db.prepare(`${this.requestSelect} WHERE r.iss = ? AND r.sub = ? ORDER BY r.id DESC LIMIT 1`).get(id.iss, id.sub) as
      | RequestRow
      | undefined;
  }
  addRequest(id: Id, name: string, message: string): number {
    return Number(
      this.db
        .prepare(`INSERT INTO requests (iss, sub, name, message, status, created_at) VALUES (?,?,?,?,'pending',?)`)
        .run(id.iss, id.sub, name, message, now()).lastInsertRowid,
    );
  }
  pendingRequests(): RequestRow[] {
    return this.db.prepare(`${this.requestSelect} WHERE r.status = 'pending' ORDER BY r.created_at`).all() as RequestRow[];
  }
  getRequest(id: number): RequestRow | undefined {
    return this.db.prepare(`${this.requestSelect} WHERE r.id = ?`).get(id) as RequestRow | undefined;
  }
  decideRequest(id: number, status: 'approved' | 'rejected', by: string) {
    this.db.prepare(`UPDATE requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`).run(status, by, now(), id);
  }
  /** A pending request is settled when the person becomes a member another way (an invitation, or added directly) */
  settleRequestsOf(id: Id, by: string) {
    this.db
      .prepare(`UPDATE requests SET status = 'approved', decided_by = ?, decided_at = ? WHERE iss = ? AND sub = ? AND status = 'pending'`)
      .run(by, now(), id.iss, id.sub);
  }

  // ---- Sessions
  insertSession(s: SessionRow) {
    this.db
      .prepare(`INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(s.id, s.iss, s.sub, s.email, s.email_verified, s.has_mfa, s.auth_at, s.id_token, s.created_at, s.last_seen);
  }
  getSession(id: string): SessionRow | undefined {
    return this.db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(id) as SessionRow | undefined;
  }
  touchSession(id: string) {
    this.db.prepare(`UPDATE sessions SET last_seen = ? WHERE id = ?`).run(now(), id);
  }
  deleteSession(id: string) {
    this.db.prepare(`DELETE FROM sessions WHERE id = ?`).run(id);
  }
  deleteSessionsOf(id: Id): number {
    return Number(this.db.prepare(`DELETE FROM sessions WHERE iss = ? AND sub = ?`).run(id.iss, id.sub).changes);
  }
  purgeSessions(idle: number, max: number) {
    const t = now();
    this.db.prepare(`DELETE FROM sessions WHERE last_seen < ? OR created_at < ?`).run(t - idle, t - max);
    this.db.prepare(`DELETE FROM logins WHERE created_at < ?`).run(t - 900);
  }

  // ---- Logins in progress (state, nonce and PKCE verifier, for 15 minutes)
  insertLogin(l: LoginRow) {
    this.db.prepare(`INSERT INTO logins VALUES (?,?,?,?,?,?)`).run(l.state, l.nonce, l.verifier, l.rd, l.step_up, l.created_at);
  }
  takeLogin(state: string): LoginRow | undefined {
    const row = this.db.prepare(`SELECT * FROM logins WHERE state = ?`).get(state) as LoginRow | undefined;
    this.db.prepare(`DELETE FROM logins WHERE state = ?`).run(state);
    if (row && row.created_at < now() - 900) return undefined;
    return row;
  }

  // ---- The log (who added or removed whom)
  log(actor: string, action: string, subject: string) {
    this.db.prepare(`INSERT INTO log (at, actor, action, subject) VALUES (?,?,?,?)`).run(now(), actor, action, subject);
  }
  recentLog(limit = 50): LogRow[] {
    return this.db.prepare(`SELECT at, actor, action, subject FROM log ORDER BY id DESC LIMIT ?`).all(limit) as LogRow[];
  }

  getMeta(key: string): string | undefined {
    return (this.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined)?.value;
  }
  setMeta(key: string, value: string) {
    this.db.prepare(`INSERT OR REPLACE INTO meta VALUES (?,?)`).run(key, value);
  }

  /** A consistent copy of the database in dir (portal-YYYY-MM-DD.db), without sessions and logins in
   *  progress (they hold tokens and are useless after a restore); keeps the newest `keep` copies. */
  backup(dir: string, keep = 7, date = new Date()): string | null {
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `portal-${date.toISOString().slice(0, 10)}.db`);
    if (existsSync(file)) return null;
    const tmp = `${file}.tmp`;
    rmSync(tmp, { force: true });
    this.db.prepare('VACUUM INTO ?').run(tmp);
    const copy = new DatabaseSync(tmp);
    copy.exec('DELETE FROM sessions; DELETE FROM logins; VACUUM;');
    copy.close();
    renameSync(tmp, file); // only a complete copy gets the final name
    const copies = readdirSync(dir).filter((f) => /^portal-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    for (const old of copies.slice(0, Math.max(0, copies.length - keep))) rmSync(join(dir, old));
    return file;
  }
}
