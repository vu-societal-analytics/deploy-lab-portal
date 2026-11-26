// services.yml (the services and their access rules) and groups.yml (who is admin, fixed members).
// Both are edited on the server (or in git) and only read by the portal: the portal never writes them.
import { readFileSync, statSync } from 'node:fs';
import { parse } from 'yaml';

export type Access = 'members' | 'admins' | 'public';

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
  /** required: a login with a second factor (asked when needed); optional: any login */
  mfa: 'required' | 'optional';
  /** Paths where a request with an Authorization header skips the lab login (the service checks its own key) */
  apiBypass: string[];
  /** Optional Caddy settings */
  maxUpload?: string;
  timeout?: string;
  /** Listed on the portal page */
  show: boolean;
};

export type Groups = {
  admin: string[];
  /** Fixed lab members, in addition to those approved in the portal */
  lab: string[];
};

const SUBDOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const UPSTREAM = /^[a-zA-Z0-9.-]+:\d{1,5}$/;
const PATH = /^\/[A-Za-z0-9._~\/-]*\*?$/;
const SIZE = /^\d+(\.\d+)?(KB|MB|GB)?$/i;
const DURATION = /^\d+(ms|s|m|h)$/;

function fail(file: string, message: string): never {
  throw new Error(`${file}: ${message}`);
}

export function parseServices(text: string, labDomain: string, file = 'services.yml'): Service[] {
  const doc = parse(text) ?? {};
  const entries = doc.services ?? {};
  if (typeof entries !== 'object' || Array.isArray(entries)) fail(file, '"services" must be a map of subdomain names');
  const services: Service[] = [];
  for (const [id, raw] of Object.entries<any>(entries)) {
    if (!SUBDOMAIN.test(id)) fail(file, `"${id}" is not a valid subdomain name`);
    if (!raw || typeof raw !== 'object') fail(file, `${id}: settings missing`);
    const known = ['name', 'description', 'upstream', 'access', 'mfa', 'api_bypass', 'max_upload', 'timeout', 'show'];
    for (const key of Object.keys(raw)) if (!known.includes(key)) fail(file, `${id}: unknown setting "${key}"`);
    const upstream = String(raw.upstream ?? '');
    if (!UPSTREAM.test(upstream)) fail(file, `${id}: upstream must be host:port, e.g. 127.0.0.1:9000`);
    const access = (raw.access ?? 'members') as Access;
    if (!['members', 'admins', 'public'].includes(access)) fail(file, `${id}: access must be members, admins or public`);
    const mfa = raw.mfa ?? 'optional';
    if (!['required', 'optional'].includes(mfa)) fail(file, `${id}: mfa must be required or optional`);
    if (access === 'public' && raw.mfa) fail(file, `${id}: mfa has no effect with access: public`);
    const apiBypass = raw.api_bypass ?? [];
    if (!Array.isArray(apiBypass) || !apiBypass.every((p: unknown) => typeof p === 'string' && PATH.test(p)))
      fail(file, `${id}: api_bypass must be a list of paths, e.g. [/api/*]`);
    if (access === 'public' && apiBypass.length) fail(file, `${id}: api_bypass has no effect with access: public`);
    if (raw.max_upload !== undefined && !SIZE.test(String(raw.max_upload))) fail(file, `${id}: max_upload must be e.g. 2.5GB`);
    if (raw.timeout !== undefined && !DURATION.test(String(raw.timeout))) fail(file, `${id}: timeout must be e.g. 3000s`);
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
      show: raw.show !== false,
    });
  }
  return services;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function parseGroups(text: string, file = 'groups.yml'): Groups {
  const doc = parse(text) ?? {};
  const groups: Groups = { admin: [], lab: [] };
  for (const [name, list] of Object.entries<any>(doc)) {
    if (name !== 'admin' && name !== 'lab') fail(file, `unknown group "${name}" (only admin and lab)`);
    if (list == null) continue;
    if (!Array.isArray(list)) fail(file, `${name} must be a list of email addresses`);
    for (const email of list) {
      if (typeof email !== 'string' || !EMAIL.test(email.trim())) fail(file, `${name}: "${email}" is not an email address`);
      groups[name].push(email.trim().toLowerCase());
    }
  }
  if (!groups.admin.length) fail(file, 'at least one admin is needed');
  return groups;
}

/** Reads both files, and reads them again when they change (checked at most every few seconds). */
export class Settings {
  services: Service[] = [];
  groups: Groups = { admin: [], lab: [] };
  private stamp = '';
  private checkedAt = 0;
  onChange?: () => void;

  constructor(private servicesFile: string, private groupsFile: string, private labDomain: string) {
    this.reload(true);
  }

  private currentStamp(): string {
    return [this.servicesFile, this.groupsFile].map((f) => statSync(f).mtimeMs).join('/');
  }

  /** Throws on invalid files at startup; later, an invalid change is logged and the last good settings stay. */
  reload(strict = false) {
    try {
      const services = parseServices(readFileSync(this.servicesFile, 'utf8'), this.labDomain, this.servicesFile);
      const groups = parseGroups(readFileSync(this.groupsFile, 'utf8'), this.groupsFile);
      this.services = services;
      this.groups = groups;
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

  serviceForHost(host: string): Service | undefined {
    return this.services.find((s) => s.host === host.toLowerCase());
  }

  isAdmin(email: string): boolean {
    return this.groups.admin.includes(email.toLowerCase());
  }
}
