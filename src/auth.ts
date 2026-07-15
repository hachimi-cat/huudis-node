import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { HuudisClaims } from './types.js';

export class HuudisAuthError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'HuudisAuthError';
  }
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(issuer: string) {
  const u = new URL(`${issuer.replace(/\/$/, '')}/.well-known/jwks.json`);
  const key = u.toString();
  let jwks = jwksCache.get(key);
  if (!jwks) {
    jwks = createRemoteJWKSet(u);
    jwksCache.set(key, jwks);
  }
  return jwks;
}

/**
 * Strip `Bearer ` prefix off an Authorization header value. Lets you pass
 * `req.headers.authorization` directly without fussing with case/prefix.
 */
function stripBearer(value: string): string {
  const m = /^\s*Bearer\s+(.+)$/i.exec(value);
  return m ? m[1]!.trim() : value.trim();
}

export interface VerifyAccessTokenOptions {
  /** Huudis issuer URL, e.g. `https://huudis.com`. Defaults to `HUUDIS_ISSUER` env. */
  issuer?: string;
  /** Expected audience, typically your `client_id`. Defaults to `HUUDIS_AUDIENCE` env. */
  audience?: string;
  /** Reject the token if it wasn't MFA-stepped-up. */
  requireMfa?: boolean;
}

/**
 * Verifies a Huudis-issued access token.
 *
 *   const claims = await verifyAccessToken(req.headers.authorization);
 *
 * Reads `HUUDIS_ISSUER` and `HUUDIS_AUDIENCE` from env when `opts` is
 * omitted — so the typical three-line middleware just works.
 */
export async function verifyAccessToken(
  tokenOrHeader: string | undefined,
  opts: VerifyAccessTokenOptions = {},
): Promise<HuudisClaims> {
  if (!tokenOrHeader) {
    throw new HuudisAuthError('MISSING_TOKEN', 'No Authorization header / token provided.');
  }
  const token = stripBearer(tokenOrHeader);

  const issuer = opts.issuer ?? process.env.HUUDIS_ISSUER;
  const audience = opts.audience ?? process.env.HUUDIS_AUDIENCE;
  if (!issuer) throw new HuudisAuthError('MISSING_ISSUER', 'Set HUUDIS_ISSUER env or pass opts.issuer.');
  if (!audience) throw new HuudisAuthError('MISSING_AUDIENCE', 'Set HUUDIS_AUDIENCE env or pass opts.audience.');

  const jwks = getJwks(issuer);
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(token, jwks, { issuer, audience });
    payload = verified.payload as Record<string, unknown>;
  } catch (e) {
    throw new HuudisAuthError('INVALID_TOKEN', (e as Error).message);
  }

  const c = payload as unknown as HuudisClaims;
  if (!c.accountId || !c.identityId || !c.identityType || !c.scope) {
    throw new HuudisAuthError('INCOMPLETE_CLAIMS', 'Token is missing required Huudis claims.');
  }
  if (opts.requireMfa && !c.mfaVerified) {
    throw new HuudisAuthError('MFA_REQUIRED', 'This operation requires an MFA-verified token.');
  }
  return c;
}
