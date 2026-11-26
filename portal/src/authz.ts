// Who may use which service: one pure function, so the rules are easy to read and to test.
import type { Service } from './settings.js';

export type Person = {
  iss: string;
  /** The account ID at the provider: membership and admin rights are by account, not by email address */
  sub: string;
  /** The login of this session used a second factor */
  hasMfa: boolean;
};

export type Membership = {
  isAdmin: (p: Person) => boolean;
  isMember: (p: Person) => boolean;
};

export type Rules = { insecureDisable2fa: boolean };

export type Decision =
  | { result: 'allow' }
  | { result: 'login' } // not signed in
  | { result: 'not-member' } // signed in, not (yet) a lab member: the portal offers a membership request
  | { result: 'not-admin' } // the service is for lab admins only
  | { result: 'mfa' }; // the service requires a second factor: sign in again with it

export function isLabMember(p: Person, m: Membership): boolean {
  return m.isAdmin(p) || m.isMember(p);
}

export function decide(service: Service, person: Person | null, m: Membership, rules: Rules): Decision {
  if (service.access === 'public') return { result: 'allow' };
  if (!person) return { result: 'login' };
  if (service.access === 'admins') {
    if (!m.isAdmin(person)) return { result: 'not-admin' };
  } else if (!isLabMember(person, m)) {
    return { result: 'not-member' };
  }
  if (service.mfa === 'required' && !person.hasMfa && !rules.insecureDisable2fa) return { result: 'mfa' };
  return { result: 'allow' };
}

/** Whether a session is still valid under the given limits (an app's own, or the portal's defaults). */
export function sessionValid(s: { created_at: number; last_seen: number }, now: number, limits: { idle: number; max: number }): boolean {
  return now - s.last_seen <= limits.idle && now - s.created_at <= limits.max;
}

/** Only addresses in the lab zone are valid places to return to after a login (no open redirect). */
export function safeReturnUrl(raw: string | undefined, labDomain: string): string {
  const fallback = `https://${labDomain}/`;
  if (!raw) return fallback;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fallback;
  }
  const host = url.hostname.toLowerCase();
  const inZone = host === labDomain || host.endsWith(`.${labDomain}`);
  if (url.protocol !== 'https:' || !inZone || url.username || url.password) return fallback;
  if (url.port && url.port !== '443') return fallback;
  return url.toString();
}
