import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '../src/db.ts';
import { Mail } from '../src/mail.ts';

test('admin notifications: at most one per hour, the rest bundled; a daily reminder', async () => {
  const db = new Db(':memory:');
  const sent: { to: string[]; subject: string }[] = [];
  const cfg: any = { smtp: { host: 'x', port: 587, user: '', password: '', from: 'lab@x.org', security: 'none' }, labName: 'Lab', portalUrl: 'https://lab.x', accountUrl: 'https://a', reminderTime: '16:00' };
  const mail = new Mail(cfg, db, () => ['admin@x.org']);
  (mail as any).transport = { sendMail: async (m: any) => { sent.push({ to: m.to, subject: m.subject }); } };

  const id = (sub: string, email: string) => (db.upsertUser({ iss: 'i', sub }, email, true), { iss: 'i', sub });
  db.addRequest(id('a', 'a@x.org'), 'A', '');
  await mail.requestReceived();
  assert.equal(sent.length, 1, 'the first request: notified at once');
  db.addRequest(id('b', 'b@x.org'), 'B', '');
  await mail.requestReceived();
  assert.equal(sent.length, 1, 'a second request within the hour: no new email yet');
  // A fixed time of day (10:00, before the reminder), with the last notification more than an hour before
  const hourLater = new Date();
  hourLater.setHours(10, 0, 0, 0);
  db.setMeta('notified_at', String(Math.floor(hourLater.getTime() / 1000) - 3601));
  await mail.tick(hourLater);
  assert.equal(sent.length, 2, 'after the hour: one bundled email');
  const evening = new Date(hourLater); evening.setHours(16, 30);
  db.setMeta('notified_at', '0');
  await mail.tick(evening);
  assert.equal(sent.length, 3, 'the daily reminder while requests are pending');
  await mail.tick(evening);
  assert.equal(sent.length, 3, 'only once a day');
  await mail.welcome('a@x.org', 'A');
  assert.deepEqual(sent[3].to, ['a@x.org']);
  await mail.invitation('c@x.org', 'C');
  assert.deepEqual(sent[4], { to: ['c@x.org'], subject: 'Invitation to the Lab' });
});
