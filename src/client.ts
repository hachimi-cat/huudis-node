import type {
  AuthorizationUrlOptions,
  AuthzCheckInput,
  AuthzCheckResult,
  HuudisClaims,
  TokenResponse,
  UserInfo,
} from './types.js';
import { verifyAccessToken, HuudisAuthError } from './auth.js';
import { ApiClient, Session } from '@forjio/sdk';
import { buildResources, type HuudisResources } from './resources.js';

export interface HuudisClientOptions {
  /** Huudis issuer URL, e.g. `https://huudis.com`. Defaults to `HUUDIS_ISSUER`. */
  issuer?: string;
  /** OIDC client_id registered in the Huudis dashboard. Defaults to `HUUDIS_CLIENT_ID`. */
  clientId?: string;
  /** Confidential client secret — required only for confidential clients
   *  (i.e. not SPAs/CLIs with PKCE). Defaults to `HUUDIS_CLIENT_SECRET`. */
  clientSecret?: string;
  /** Audience claim expected on issued access tokens. Defaults to the
   *  clientId if not provided. */
  audience?: string;
  /** Optional override for the protected-API base URL. Defaults to issuer. */
  apiBase?: string;
  /** When set, resource methods auto-attach this session's bearer and
   *  refresh proactively. Without a session, callers must pass
   *  `{ authToken }` per call. */
  session?: Session;
  /** Test seam — override fetch used by both the ApiClient and OIDC
   *  token endpoint calls. */
  fetchImpl?: typeof fetch;
}

/**
 * High-level client wrapping every developer-facing Huudis endpoint.
 *
 * For JWT verification only, `verifyAccessToken(...)` on its own is
 * enough — but most servers want the OIDC code-flow helpers (server-side)
 * and most CLIs want the resource namespaces (`client.iam.listUsers()`).
 */
export class HuudisClient {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly clientSecret?: string;
  private readonly audience: string;
  private readonly apiBase: string;
  private readonly fetchImpl: typeof fetch;
  private readonly api: ApiClient;

  // Resource namespaces (huudis admin API)
  readonly iam: HuudisResources['iam'];
  readonly identityProviders: HuudisResources['identityProviders'];
  readonly assumedSessions: HuudisResources['assumedSessions'];
  readonly authz: HuudisResources['authz'];
  readonly workspaces: HuudisResources['workspaces'];
  readonly endUsers: HuudisResources['endUsers'];
  readonly mfa: HuudisResources['mfa'];
  readonly oidcClients: HuudisResources['oidcClients'];
  readonly connectedApps: HuudisResources['connectedApps'];
  readonly services: HuudisResources['services'];
  readonly webhookSubscriptions: HuudisResources['webhookSubscriptions'];
  readonly billing: HuudisResources['billing'];
  readonly account: HuudisResources['account'];

  constructor(opts: HuudisClientOptions = {}) {
    const issuer = opts.issuer ?? process.env.HUUDIS_ISSUER;
    const clientId = opts.clientId ?? process.env.HUUDIS_CLIENT_ID;
    const clientSecret = opts.clientSecret ?? process.env.HUUDIS_CLIENT_SECRET;
    if (!issuer) throw new HuudisAuthError('MISSING_ISSUER', 'Set HUUDIS_ISSUER env or pass opts.issuer.');
    if (!clientId) throw new HuudisAuthError('MISSING_CLIENT_ID', 'Set HUUDIS_CLIENT_ID env or pass opts.clientId.');
    this.issuer = issuer.replace(/\/$/, '');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.audience = opts.audience ?? clientId;
    this.apiBase = (opts.apiBase ?? this.issuer).replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl ?? fetch;

    this.api = new ApiClient({
      baseUrl: this.apiBase,
      session: opts.session,
      fetchImpl: this.fetchImpl,
    });

    const resources = buildResources(this.api);
    this.iam = resources.iam;
    this.identityProviders = resources.identityProviders;
    this.assumedSessions = resources.assumedSessions;
    this.authz = resources.authz;
    this.workspaces = resources.workspaces;
    this.endUsers = resources.endUsers;
    this.mfa = resources.mfa;
    this.oidcClients = resources.oidcClients;
    this.connectedApps = resources.connectedApps;
    this.services = resources.services;
    this.webhookSubscriptions = resources.webhookSubscriptions;
    this.billing = resources.billing;
    this.account = resources.account;
  }

  /** Shortcut — same as the module-level `verifyAccessToken` with the
   *  client's issuer + audience pre-applied. */
  async verifyAccessToken(tokenOrHeader: string | undefined, extra: { requireMfa?: boolean } = {}): Promise<HuudisClaims> {
    return verifyAccessToken(tokenOrHeader, {
      issuer: this.issuer,
      audience: this.audience,
      requireMfa: extra.requireMfa,
    });
  }

  /** Build a redirect URL to send the user to Huudis for sign-in. */
  authorizationUrl(opts: AuthorizationUrlOptions): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: opts.redirectUri,
      scope: opts.scope ?? 'openid profile email',
      state: opts.state,
    });
    if (opts.codeChallenge) {
      params.set('code_challenge', opts.codeChallenge);
      params.set('code_challenge_method', opts.codeChallengeMethod ?? 'S256');
    }
    if (opts.loginHint) params.set('login_hint', opts.loginHint);
    if (opts.idpHint) params.set('idp_hint', opts.idpHint);
    return `${this.issuer}/api/v1/oidc/authorize?${params.toString()}`;
  }

  /** Exchange an email + password for tokens via the Resource Owner
   *  Password Credentials grant. Requires a first-party OIDC client
   *  (confidential client_secret, trusted UI). */
  async passwordGrant(input: {
    email: string;
    password: string;
    scope?: string;
  }): Promise<TokenResponse> {
    return this.tokenEndpoint({
      grant_type: 'password',
      username: input.email,
      password: input.password,
      client_id: this.clientId,
      ...(this.clientSecret ? { client_secret: this.clientSecret } : {}),
      ...(input.scope ? { scope: input.scope } : {}),
    });
  }

  /** Register a new Huudis user and immediately mint tokens. Uses the
   *  Forjio-custom `urn:forjio:grant-type:signup` grant type. */
  async signupDirect(input: {
    email: string;
    password: string;
    name?: string;
    scope?: string;
  }): Promise<TokenResponse> {
    return this.tokenEndpoint({
      grant_type: 'urn:forjio:grant-type:signup',
      email: input.email,
      password: input.password,
      client_id: this.clientId,
      ...(this.clientSecret ? { client_secret: this.clientSecret } : {}),
      ...(input.name ? { name: input.name } : {}),
      ...(input.scope ? { scope: input.scope } : {}),
    });
  }

  /** Exchange an authorization code for tokens. */
  async exchangeCode(input: {
    code: string;
    redirectUri: string;
    codeVerifier?: string;
  }): Promise<TokenResponse> {
    return this.tokenEndpoint({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: this.clientId,
      ...(this.clientSecret ? { client_secret: this.clientSecret } : {}),
      ...(input.codeVerifier ? { code_verifier: input.codeVerifier } : {}),
    });
  }

  /** Exchange a refresh token for a fresh access token. */
  async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
    return this.tokenEndpoint({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.clientId,
      ...(this.clientSecret ? { client_secret: this.clientSecret } : {}),
    });
  }

  /** Fetch the OIDC userinfo for a given access token. */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const res = await this.fetchImpl(`${this.issuer}/api/v1/oidc/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      throw new HuudisAuthError('USERINFO_FAILED', `HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json() as Promise<UserInfo>;
  }

  /** Ask Huudis "is this principal allowed to do this action?".
   *  Legacy helper — prefer `client.authz.check()` going forward. */
  async authzCheck(
    input: AuthzCheckInput,
    opts: { accessToken: string },
  ): Promise<AuthzCheckResult> {
    return this.authz.check(input, { authToken: opts.accessToken });
  }

  private async tokenEndpoint(body: Record<string, string>): Promise<TokenResponse> {
    const res = await this.fetchImpl(`${this.issuer}/api/v1/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });
    const text = await res.text();
    let parsed: TokenResponse & { error?: string; error_description?: string } | null = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
    if (!res.ok) {
      const msg = parsed?.error_description ?? parsed?.error ?? `HTTP ${res.status}`;
      throw new HuudisAuthError('TOKEN_ENDPOINT_FAILED', msg);
    }
    return parsed as TokenResponse;
  }
}
