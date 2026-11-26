// Email (optional, with SMTP settings in .env): notifications to the lab admins about membership requests
// (at most one per hour, and a daily reminder while requests are pending), and a welcome to new members.
import nodemailer from 'nodemailer';
import type { Config } from './config.js';
import type { Db } from './db.js';
import type { Settings } from './settings.js';

const HOUR = 3600;

export class Mail {
  private transport: ReturnType<typeof nodemailer.createTransport> | null;

  constructor(private cfg: Config, private db: Db, private settings: Settings) {
    this.transport = cfg.smtp
      ? nodemailer.createTransport({
          host: cfg.smtp.host,
          port: cfg.smtp.port,
          secure: cfg.smtp.security === 'tls',
          requireTLS: cfg.smtp.security === 'starttls',
          ignoreTLS: cfg.smtp.security === 'none',
          auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.password } : undefined,
        })
      : null;
  }

  get enabled() {
    return !!this.transport;
  }

  private async send(to: string[], subject: string, text: string) {
    if (!this.transport || !to.length) return;
    try {
      await this.transport.sendMail({ from: this.cfg.smtp!.from, to, subject, text });
    } catch (error) {
      console.error(`Email "${subject}" not sent: ${(error as Error).message}`);
    }
  }

  private summary(): string {
    const pending = this.db.pendingRequests();
    const lines = pending.map((r) => `- ${r.name} <${r.email}>${r.message ? `: ${r.message.slice(0, 200)}` : ''}`);
    return `${pending.length} pending membership request(s) for the ${this.cfg.labName}:\n\n${lines.join('\n')}\n\nApprove or reject them on the admin page: ${this.cfg.portalUrl}/admin\n`;
  }

  /** A new request: notify now, unless a notification went out in the last hour (then it follows later). */
  async requestReceived() {
    const last = Number(this.db.getMeta('notified_at') ?? 0);
    if (Date.now() / 1000 - last < HOUR) {
      this.db.setMeta('notify_due', '1');
      return;
    }
    await this.notifyAdmins();
  }

  private async notifyAdmins() {
    this.db.setMeta('notified_at', String(Math.floor(Date.now() / 1000)));
    this.db.setMeta('notify_due', '0');
    if (!this.db.pendingRequests().length) return;
    await this.send(this.settings.groups.admin, `Lab membership requests`, this.summary());
  }

  /** Runs every minute: the delayed notification, and the daily reminder. */
  async tick(now = new Date()) {
    const last = Number(this.db.getMeta('notified_at') ?? 0);
    if (this.db.getMeta('notify_due') === '1' && now.getTime() / 1000 - last >= HOUR) await this.notifyAdmins();
    const today = now.toLocaleDateString('sv'); // local date, YYYY-MM-DD
    const hhmm = now.toTimeString().slice(0, 5);
    if (hhmm >= this.cfg.reminderTime && this.db.getMeta('reminded_on') !== today) {
      this.db.setMeta('reminded_on', today);
      if (this.db.pendingRequests().length) await this.notifyAdmins();
    }
  }

  async welcome(email: string, name: string) {
    await this.send(
      [email],
      `Welcome to the ${this.cfg.labName}`,
      `Hello ${name},\n\nYou are now a member of the ${this.cfg.labName}. The lab's services are listed on ${this.cfg.portalUrl}\n\n` +
        `Please protect your account with a second factor (an authenticator app or a passkey): ${this.cfg.accountUrl} (Account security, Signing in).\n`,
    );
  }
}
