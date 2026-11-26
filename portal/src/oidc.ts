// The login with the OIDC provider, with openid-client: authorization code flow with PKCE, state and nonce;
// sign-out. The portal keeps its own sessions after the login (like AmCAT and AnnoTinder).
import * as client from 'openid-client';
import type { Config, MfaClaim } from './config.js';

export type LoginResult = {
  iss: string;
  sub: string;
  email: string;
  emailVerified: boolean;
  hasMfa: boolean;
  authAt: number;
  idToken: string;
};

export function hasMfa(claims: Record<string, unknown>, mfa: MfaClaim): boolean {
  const value = claims[mfa.claim];
  if (mfa.claim === 'amr') return Array.isArray(value) && value.includes(mfa.value);
  return value === mfa.value;
}

export class Oidc {
  private constructor(
    private cfg: Config,
    private config: client.Configuration,
  ) {}

  static async create(cfg: Config): Promise<Oidc> {
    const options = cfg.allowInsecureIssuer ? { execute: [client.allowInsecureRequests] } : undefined;
    const config = await client.discovery(new URL(cfg.oidcHost), cfg.oidcClientId, cfg.oidcClientSecret, undefined, options);
    return new Oidc(cfg, config);
  }

  /** The provider's issuer: the only one whose logins the portal accepts */
  get issuer(): string {
    return this.config.serverMetadata().issuer;
  }

  get redirectUri() {
    return `${this.cfg.portalUrl}/callback`;
  }

  /** The URL to send the user to; maxAge 0 asks for a fresh login (with the second factor, if the user has one).
   *  A fresh login also sends prompt=login: Keycloak skips max_age=0 within the second of the last login. */
  async start(maxAge?: number) {
    const verifier = client.randomPKCECodeVerifier();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const params: Record<string, string> = {
      redirect_uri: this.redirectUri,
      scope: 'openid email',
      code_challenge: await client.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
    };
    if (maxAge !== undefined) params.max_age = String(maxAge);
    if (maxAge === 0) params.prompt = 'login';
    return { url: client.buildAuthorizationUrl(this.config, params).toString(), state, nonce, verifier };
  }

  /** Exchanges the code; openid-client checks state, nonce, PKCE, issuer, audience and the signature. */
  async finish(callbackPath: string, expected: { state: string; nonce: string; verifier: string }): Promise<LoginResult> {
    const tokens = await client.authorizationCodeGrant(this.config, new URL(callbackPath, this.cfg.portalUrl), {
      pkceCodeVerifier: expected.verifier,
      expectedState: expected.state,
      expectedNonce: expected.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error('No ID token');
    const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : '';
    if (!email) throw new Error('The ID token has no email address (scope email)');
    return {
      iss: claims.iss,
      sub: claims.sub,
      email,
      emailVerified: claims.email_verified === true,
      hasMfa: hasMfa(claims, this.cfg.mfaClaim),
      authAt: typeof claims.auth_time === 'number' ? claims.auth_time : Math.floor(Date.now() / 1000),
      idToken: tokens.id_token!,
    };
  }

  endSessionUrl(idToken: string, postLogoutRedirect: string): string {
    return client
      .buildEndSessionUrl(this.config, { id_token_hint: idToken, post_logout_redirect_uri: postLogoutRedirect })
      .toString();
  }
}
