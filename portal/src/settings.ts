// services.yml (the services and their access rules) and admins.yml (the lab admins, by account ID).
// Both are edited on the server and only read by the portal: the portal never writes them.
// Everything the portal itself changes (members, invitations, requests) is in its database.
import { readFileSync, statSync } from 'node:fs';
import { parse } from 'yaml';

export type Access = 'members' | 'admins' | 'public';

/** How long a session lasts: idle (seconds without use) and max (seconds since the login) */
export type SessionLimits = { idle: number; max: number };

export type Service = {
  /** The subdomain: <id>.<lab domain> */
  id: string;
  host: string;
  name: string;
  description: string;
  /** Where Caddy sends the requests, e.g. 127.0.0.1:9000 */
  upstream: string;
  /** members: lab members; admins: lab admins; public: no lab login (the service has its own, or is public) */
  access: Access;
  /** required: a login with a second factor (asked when needed); optional: any login. Always set explicitly. */
  mfa: 'required' | 'optional';
  /** Paths where a request with an Authorization header skips the lab login (the service checks its own key) */
  apiBypass: string[];
  /** Optional Caddy settings */
  maxUpload?: string;
  timeout?: string;
  /** Session limits for this app, in seconds, instead of the portal's defaults (SESSION_IDLE, SESSION_MAX):
   *  e.g. for a notebook server that runs for hours without the user doing anything */
  sessionIdle?: number;
  sessionMax?: number;
  /** Listed on the portal page */
  show: boolean;
};

/** An old address that now redirects (permanently, keeping the path) to another site, e.g. after a move under lab. */
export type Redirect = { from: string; to: string };

/** A lab admin: the account ID (the sub claim of the provider) and a name, for people reading the file. */
export type Admin = { sub: string; name: string };

const HOSTNAME = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const SUBDOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const UPSTREAM = /^[a-zA-Z0-9.-]+:\d{1,5}$/;
const PATH = /^\/[A-Za-z0-9._~\/-]*\*?$/;
const SIZE = /^\d+(\.\d+)?(KB|MB|GB)?$/i;
const DURATION = /^\d+(ms|s|m|h)$/;
const SPAN = /^(\d+)(s|m|h|d)$/;
const SPAN_SECONDS = { s: 1, m: 60, h: 3600, d: 86400 } as const;

/** A time span like 30m, 8h or 7d, in seconds */
export function parseSpan(value: unknown): number | undefined {
  const m = SPAN.exec(String(value));
  if (!m || Number(m[1]) <= 0) return undefined;
  return Number(m[1]) * SPAN_SECONDS[m[2] as keyof typeof SPAN_SECONDS];
}

function fail(file: string, message: string): never {
  throw new Error(`${file}: ${message}`);
}

export function parseServices(text: string, labDomain: string, file = 'services.yml'): Service[] {
  const doc = parse(text) ?? {};
  for (const key of Object.keys(doc)) if (key !== 'services' && key !== 'redirects') fail(file, `unknown section "${key}" (only services and redirects)`);
  const entries = doc.services ?? {};
  if (typeof entries !== 'object' || Array.isArray(entries)) fail(file, '"services" must be a map of subdomain names');
  const services: Service[] = [];
  for (const [id, raw] of Object.entries<any>(entries)) {
    if (!SUBDOMAIN.test(id)) fail(file, `"${id}" is not a valid subdomain name`);
    if (!raw || typeof raw !== 'object') fail(file, `${id}: settings missing`);
    const known = ['name', 'description', 'upstream', 'access', 'mfa', 'api_bypass', 'max_upload', 'timeout', 'session_idle', 'session_max', 'show'];
    for (const key of Object.keys(raw)) if (!known.includes(key)) fail(file, `${id}: unknown setting "${key}"`);
    const upstream = String(raw.upstream ?? '');
    if (!UPSTREAM.test(upstream)) fail(file, `${id}: upstream must be host:port, e.g. 127.0.0.1:9000`);
    const access = (raw.access ?? 'members') as Access;
    if (!['members', 'admins', 'public'].includes(access)) fail(file, `${id}: access must be members, admins or public`);
    if (access === 'public' && raw.mfa !== undefined) fail(file, `${id}: mfa has no effect with access: public`);
    const mfa = access === 'public' ? 'optional' : raw.mfa;
    if (!['required', 'optional'].includes(mfa)) fail(file, `${id}: set mfa to required or optional (whether the service needs a login with a second factor)`);
    const apiBypass = raw.api_bypass ?? [];
    if (!Array.isArray(apiBypass) || !apiBypass.every((p: unknown) => typeof p === 'string' && PATH.test(p)))
      fail(file, `${id}: api_bypass must be a list of paths, e.g. [/api/*]`);
    if (access === 'public' && apiBypass.length) fail(file, `${id}: api_bypass has no effect with access: public`);
    if (raw.max_upload !== undefined && !SIZE.test(String(raw.max_upload))) fail(file, `${id}: max_upload must be e.g. 2.5GB`);
    if (raw.timeout !== undefined && !DURATION.test(String(raw.timeout))) fail(file, `${id}: timeout must be e.g. 3000s`);
    const span = {} as { session_idle?: number; session_max?: number };
    for (const key of ['session_idle', 'session_max'] as const) {
      if (raw[key] === undefined) continue;
      if (access === 'public') fail(file, `${id}: ${key} has no effect with access: public`);
      span[key] = parseSpan(raw[key]);
      if (span[key] === undefined) fail(file, `${id}: ${key} must be e.g. 30m, 8h or 7d`);
    }
    services.push({
      id,
      host: `${id}.${labDomain}`,
      name: String(raw.name ?? id),
      description: String(raw.description ?? ''),
      upstream,
      access,
      mfa,
      apiBypass,
      maxUpload: raw.max_upload !== undefined ? String(raw.max_upload) : undefined,
      timeout: raw.timeout !== undefined ? String(raw.timeout) : undefined,
      sessionIdle: span.session_idle,
      sessionMax: span.session_max,
      show: raw.show !== false,
    });
  }
  return services;
}

/** The redirects section of services.yml: old address -> the origin it moved to (https://...). */
export function parseRedirects(text: string, labDomain: string, services: Service[], file = 'services.yml'): Redirect[] {
  const entries = (parse(text) ?? {}).redirects ?? {};
  if (typeof entries !== 'object' || Array.isArray(entries)) fail(file, '"redirects" must be a map of old address: new address');
  const taken = new Set([labDomain, ...services.map((s) => s.host)]);
  return Object.entries<any>(entries).map(([from, to]) => {
    if (!HOSTNAME.test(from)) fail(file, `redirects: "${from}" is not a host name, e.g. whisper.example.org`);
    if (taken.has(from)) fail(file, `redirects: ${from} is already the portal or a service`);
    let url: URL | undefined;
    try {
      url = new URL(String(to));
    } catch {
      // checked below
    }
    if (!url || url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || String(to).replace(/\/$/, '') !== url.origin)
      fail(file, `redirects: ${from} must point to an address like https://whisper.${labDomain}`);
    return { from, to: url.origin };
  });
}

const ACCOUNT_ID = /^[A-Za-z0-9._:@|-]{1,255}$/;

export function parseAdmins(text: string, file = 'admins.yml'): Admin[] {
  const doc = parse(text) ?? {};
  for (const key of Object.keys(doc)) if (key !== 'admins') fail(file, `unknown section "${key}" (only admins)`);
  const entries = doc.admins ?? {};
  if (typeof entries !== 'object' || Array.isArray(entries)) fail(file, '"admins" must be a map of account ID: name');
  const admins = Object.entries<any>(entries).map(([sub, name]) => {
    if (!ACCOUNT_ID.test(sub)) fail(file, `"${sub}" is not an account ID (shown at the bottom of the portal when signed in)`);
    if (typeof name !== 'string' || !name.trim()) fail(file, `${sub}: give a name, e.g. ${sub}: Jane Doe`);
    return { sub, name: name.trim() };
  });
  if (!admins.length) fail(file, 'at least one admin is needed');
  return admins;
}

/** Reads both files, and reads them again when they change (checked at most every few seconds). */
export class Settings {
  services: Service[] = [];
  redirects: Redirect[] = [];
  admins: Admin[] = [];
  private stamp = '';
  private checkedAt = 0;
  onChange?: () => void;

  constructor(private servicesFile: string, private adminsFile: string, private labDomain: string) {
    this.reload(true);
  }

  private currentStamp(): string {
    return [this.servicesFile, this.adminsFile].map((f) => statSync(f).mtimeMs).join('/');
  }

  /** Throws on invalid files at startup; later, an invalid change is logged and the last good settings stay. */
  reload(strict = false) {
    try {
      const text = readFileSync(this.servicesFile, 'utf8');
      const services = parseServices(text, this.labDomain, this.servicesFile);
      const redirects = parseRedirects(text, this.labDomain, services, this.servicesFile);
      const admins = parseAdmins(readFileSync(this.adminsFile, 'utf8'), this.adminsFile);
      this.services = services;
      this.redirects = redirects;
      this.admins = admins;
      this.stamp = this.currentStamp();
      this.onChange?.();
    } catch (error) {
      if (strict) throw error;
      console.error(`Settings not reloaded: ${(error as Error).message}`);
      this.stamp = this.currentStamp();
    }
  }

  /** Called on requests: reloads when a file changed. */
  refresh() {
    const now = Date.now();
    if (now - this.checkedAt < 3000) return;
    this.checkedAt = now;
    try {
      if (this.currentStamp() !== this.stamp) this.reload();
    } catch (error) {
      console.error(`Settings not checked: ${(error as Error).message}`);
    }
  }

  /** The most generous limits of all apps and the defaults: how long a session may be kept at all */
  longestSession(defaults: SessionLimits): SessionLimits {
    return {
      idle: Math.max(defaults.idle, ...this.services.map((s) => s.sessionIdle ?? 0)),
      max: Math.max(defaults.max, ...this.services.map((s) => s.sessionMax ?? 0)),
    };
  }

  serviceForHost(host: string): Service | undefined {
    return this.services.find((s) => s.host === host.toLowerCase());
  }

  /** Admins are listed by account ID; the portal accepts logins from one provider only. */
  isAdmin(sub: string): boolean {
    return this.admins.some((a) => a.sub === sub);
  }
}
