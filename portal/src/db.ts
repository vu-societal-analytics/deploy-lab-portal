// The portal's own data, in one SQLite file in ./data: sessions, pending logins, lab members approved
// in the portal, membership requests, and a log of admin actions. A daily copy (without the sessions)
// goes to ./backups, which the server's backup picks up.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readdirSync, renameSync, rmSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

export type SessionRow = {
  id: string;
  email: string;
  sub: string;
  sid: string | null;
  email_verified: number;
  has_mfa: number;
  auth_at: number;
  id_token: string;
  refresh_token: string | null;
  created_at: number;
  last_seen: number;
  checked_at: number;
};

export type RequestRow = {
  id: number;
  email: string;
  name: string;
  message: string;
  status: 'pending' | 'approved' | 'rejected';
  created_at: number;
  decided_by: string | null;
  decided_at: number | null;
};

export type MemberRow = { email: string; name: string; added_by: string; added_at: number };

export type LoginRow = { state: string; nonce: string; verifier: string; rd: string; step_up: number; created_at: number };

const now = () => Math.floor(Date.now() / 1000);

export class Db {
  private db: DatabaseSync;

  constructor(file: string) {
    if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, email TEXT NOT NULL, sub TEXT NOT NULL, sid TEXT,
        email_verified INTEGER NOT NULL, has_mfa INTEGER NOT NULL, auth_at INTEGER NOT NULL,
        id_token TEXT NOT NULL, refresh_token TEXT,
        created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, checked_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS sessions_sid ON sessions (sid);
      CREATE INDEX IF NOT EXISTS sessions_sub ON sessions (sub);
      CREATE TABLE IF NOT EXISTS logins (
        state TEXT PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, rd TEXT NOT NULL,
        step_up INTEGER NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS members (
        email TEXT PRIMARY KEY, name TEXT NOT NULL, added_by TEXT NOT NULL, added_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, name TEXT NOT NULL, message TEXT NOT NULL,
        status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_by TEXT, decided_at INTEGER);
      CREATE TABLE IF NOT EXISTS log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
        subject TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    `);
  }

  // Sessions
  insertSession(s: SessionRow) {
    this.db
      .prepare(`INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(s.id, s.email, s.sub, s.sid, s.email_verified, s.has_mfa, s.auth_at, s.id_token, s.refresh_token, s.created_at, s.last_seen, s.checked_at);
  }
  getSession(id: string): SessionRow | undefined {
    return this.db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(id) as SessionRow | undefined;
  }
  touchSession(id: string) {
    this.db.prepare(`UPDATE sessions SET last_seen = ? WHERE id = ?`).run(now(), id);
  }
  updateSessionTokens(id: string, refreshToken: string | null, idToken?: string) {
    this.db
      .prepare(`UPDATE sessions SET refresh_token = ?, id_token = COALESCE(?, id_token), checked_at = ? WHERE id = ?`)
      .run(refreshToken, idToken ?? null, now(), id);
  }
  deleteSession(id: string) {
    this.db.prepare(`DELETE FROM sessions WHERE id = ?`).run(id);
  }
  deleteSessionsBy(field: 'sid' | 'sub', value: string): number {
    return Number(this.db.prepare(`DELETE FROM sessions WHERE ${field} = ?`).run(value).changes);
  }
  deleteSessionsOf(email: string) {
    this.db.prepare(`DELETE FROM sessions WHERE email = ?`).run(email);
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

  purgeSessions(idle: number, max: number) {
    const t = now();
    this.db.prepare(`DELETE FROM sessions WHERE last_seen < ? OR created_at < ?`).run(t - idle, t - max);
    this.db.prepare(`DELETE FROM logins WHERE created_at < ?`).run(t - 900);
  }

  // Logins in progress (state, nonce and PKCE verifier, for 15 minutes)
  insertLogin(l: LoginRow) {
    this.db.prepare(`INSERT INTO logins VALUES (?,?,?,?,?,?)`).run(l.state, l.nonce, l.verifier, l.rd, l.step_up, l.created_at);
  }
  takeLogin(state: string): LoginRow | undefined {
    const row = this.db.prepare(`SELECT * FROM logins WHERE state = ?`).get(state) as LoginRow | undefined;
    this.db.prepare(`DELETE FROM logins WHERE state = ?`).run(state);
    if (row && row.created_at < now() - 900) return undefined;
    return row;
  }

  // Members approved in the portal
  isMember(email: string): boolean {
    return !!this.db.prepare(`SELECT 1 FROM members WHERE email = ?`).get(email);
  }
  members(): MemberRow[] {
    return this.db.prepare(`SELECT * FROM members ORDER BY email`).all() as MemberRow[];
  }
  addMember(email: string, name: string, by: string) {
    this.db.prepare(`INSERT OR REPLACE INTO members VALUES (?,?,?,?)`).run(email, name, by, now());
  }
  removeMember(email: string): boolean {
    return Number(this.db.prepare(`DELETE FROM members WHERE email = ?`).run(email).changes) > 0;
  }

  // Membership requests
  pendingRequestOf(email: string): RequestRow | undefined {
    return this.db.prepare(`SELECT * FROM requests WHERE email = ? AND status = 'pending'`).get(email) as RequestRow | undefined;
  }
  addRequest(email: string, name: string, message: string): number {
    return Number(
      this.db
        .prepare(`INSERT INTO requests (email, name, message, status, created_at) VALUES (?,?,?,'pending',?)`)
        .run(email, name, message, now()).lastInsertRowid,
    );
  }
  pendingRequests(): RequestRow[] {
    return this.db.prepare(`SELECT * FROM requests WHERE status = 'pending' ORDER BY created_at`).all() as RequestRow[];
  }
  getRequest(id: number): RequestRow | undefined {
    return this.db.prepare(`SELECT * FROM requests WHERE id = ?`).get(id) as RequestRow | undefined;
  }
  decideRequest(id: number, status: 'approved' | 'rejected', by: string) {
    this.db.prepare(`UPDATE requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`).run(status, by, now(), id);
  }

  // The log of admin actions (who added or removed whom)
  log(actor: string, action: string, subject: string) {
    this.db.prepare(`INSERT INTO log (at, actor, action, subject) VALUES (?,?,?,?)`).run(now(), actor, action, subject);
  }
  recentLog(limit = 50): { at: number; actor: string; action: string; subject: string }[] {
    return this.db.prepare(`SELECT at, actor, action, subject FROM log ORDER BY id DESC LIMIT ?`).all(limit) as any[];
  }

  getMeta(key: string): string | undefined {
    return (this.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as { value: string } | undefined)?.value;
  }
  setMeta(key: string, value: string) {
    this.db.prepare(`INSERT OR REPLACE INTO meta VALUES (?,?)`).run(key, value);
  }
}
