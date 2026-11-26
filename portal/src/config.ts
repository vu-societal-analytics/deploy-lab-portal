// Settings from the environment (.env). Names follow the lab's Authentication standard where they overlap.

function env(name: string, fallback?: string): string {
  const value = process.env[name]?.trim();
  if (value) return value;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing setting: ${name} (in .env)`);
}

function flag(name: string): boolean {
  return ['true', '1', 'yes'].includes((process.env[name] ?? '').trim().toLowerCase());
}

function seconds(name: string, fallback: number): number {
  const value = Number(env(name, String(fallback)));
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a number of seconds`);
  return value;
}

export type MfaClaim = { claim: 'amr' | 'acr'; value: string };

function mfaClaim(): MfaClaim {
  const raw = env('OIDC_MFA_CLAIM', 'amr:mfa');
  const [claim, ...rest] = raw.split(':');
  const value = rest.join(':');
  if ((claim !== 'amr' && claim !== 'acr') || !value) throw new Error('OIDC_MFA_CLAIM must be amr:<value> or acr:<value>');
  return { claim, value };
}

export function loadConfig() {
  const labDomain = env('LAB_DOMAIN').toLowerCase().replace(/^\.+|\.+$/g, '');
  const config = {
    /** The lab zone: the portal at https://<labDomain>, the services at https://<name>.<labDomain> */
    labDomain,
    portalUrl: `https://${labDomain}`,
    /** Where the portal listens (Caddy proxies to it) */
    listenHost: env('PORTAL_LISTEN_HOST', '0.0.0.0'),
    listenPort: Number(env('PORTAL_PORT', '3000')),
    /** The OIDC provider (the realm of Keycloak that AmCAT and AnnoTinder use too) */
    oidcHost: env('OIDC_HOST'),
    oidcClientId: env('OIDC_CLIENT_ID'),
    oidcClientSecret: env('OIDC_CLIENT_SECRET'),
    mfaClaim: mfaClaim(),
    /** Sensitive actions (the admin page) need a 2FA login at most this old */
    stepUpMaxAge: seconds('AUTH_STEP_UP_MAX_AGE', 600),
    insecureDisable2fa: flag('AUTH_INSECURE_DISABLE_2FA'),
    insecureDisableEmailVerification: flag('AUTH_INSECURE_DISABLE_EMAIL_VERIFICATION'),
    /** The portal's own sessions: signed out after this long without use, and at most this long in total
     *  (OWASP's idle and absolute timeouts, with NIST SP 800-63B's numbers for logins with a second factor).
     *  Apps can have their own limits in services.yml. Independent of the provider's session. */
    sessionIdle: seconds('SESSION_IDLE', 30 * 60),
    sessionMax: seconds('SESSION_MAX', 12 * 3600),
    /** Where users manage their account and 2FA (the account console of the realm) */
    accountUrl: env('ACCOUNT_URL', `${env('OIDC_HOST').replace(/\/+$/, '')}/account`),
    /** Files */
    servicesFile: env('SERVICES_FILE', '/config/services.yml'),
    adminsFile: env('ADMINS_FILE', '/config/admins.yml'),
    caddyFile: env('CADDY_FILE', '/caddy/Caddyfile'),
    databaseFile: env('DATABASE_FILE', '/data/portal.db'),
    /** A daily copy of the database (empty: none) */
    backupDir: env('BACKUP_DIR', ''),
    /** The address Caddy proxies the portal to */
    portalUpstream: env('PORTAL_UPSTREAM', '127.0.0.1:3000'),
    acmeEmail: env('ACME_EMAIL', ''),
    /** Email (optional): notifications to admins, invitations, and a welcome to new members */
    smtp: process.env.SMTP_HOST
      ? {
          host: env('SMTP_HOST'),
          port: Number(env('SMTP_PORT', '587')),
          user: env('SMTP_USER', ''),
          password: env('SMTP_PASSWORD', ''),
          from: env('SMTP_FROM'),
          /** starttls (port 587, default), tls (port 465), or none (only for a local relay) */
          security: env('SMTP_SECURITY', 'starttls') as 'starttls' | 'tls' | 'none',
        }
      : null,
    /** The daily reminder about pending requests, as HH:MM (server time) */
    reminderTime: env('REMINDER_TIME', '16:00'),
    labName: env('LAB_NAME', 'Societal Analytics Lab'),
    /** The realm lets people create an account themselves (then they request membership here) */
    registrationOpen: flag('REGISTRATION_OPEN'),
    /** Only for tests: allows http:// for the OIDC provider, and lets Caddy use its own local certificates */
    allowInsecureIssuer: flag('TEST_ALLOW_HTTP_ISSUER'),
    localCerts: flag('TEST_LOCAL_CERTS'),
  };
  return config;
}

export type Config = ReturnType<typeof loadConfig>;
