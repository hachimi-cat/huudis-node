import { createHash, createHmac } from 'node:crypto';

/** An IAM access key: the AKIA… id and the secret shown once at creation. */
export interface AccessKeyCredentials {
  accessKeyId: string;
  secretAccessKey: string;
}

/** An OIDC client's credentials — what `/api/v1/app/*` takes. */
export interface ClientCredentials {
  clientId: string;
  clientSecret: string;
}

/**
 * Sign one request with an access key (`Huudis-HMAC-SHA256`):
 *
 *   StringToSign = METHOD "\n" PATH-WITH-QUERY "\n" X-Huudis-Date "\n" hex(sha256(body))
 *   Signature    = hex(HMAC-SHA256(secret, StringToSign))
 *
 * PATH-WITH-QUERY is exactly what goes on the request line (`/api/v1/iam/users?x=1`);
 * the body is the exact bytes sent (empty for none). Huudis accepts an X-Huudis-Date
 * within 5 minutes of its clock. Returns the two headers to send.
 */
export function signRequest(
  creds: AccessKeyCredentials,
  input: { method: string; url: string | URL; body?: string | Uint8Array | null; date?: Date },
): { authorization: string; 'x-huudis-date': string } {
  const url = typeof input.url === 'string' ? new URL(input.url) : input.url;
  const date = (input.date ?? new Date()).toISOString();
  const bodyHash = createHash('sha256').update(input.body ?? '').digest('hex');
  const stringToSign = `${input.method.toUpperCase()}\n${url.pathname}${url.search}\n${date}\n${bodyHash}`;
  const signature = createHmac('sha256', creds.secretAccessKey).update(stringToSign).digest('hex');
  return {
    authorization: `Huudis-HMAC-SHA256 Credential=${creds.accessKeyId}, Signature=${signature}`,
    'x-huudis-date': date,
  };
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

/**
 * A fetch that signs every request with the access key. A request that already
 * carries an Authorization header (a per-call `authToken`) is sent as it is.
 */
export function accessKeyFetch(creds: AccessKeyCredentials, baseFetch: typeof fetch = fetch): typeof fetch {
  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (!headers.has('authorization')) {
      const body = init.body ?? undefined;
      if (body !== undefined && typeof body !== 'string' && !(body instanceof Uint8Array)) {
        throw new TypeError('Huudis access-key signing needs a string or byte body');
      }
      const signed = signRequest(creds, { method: init.method ?? 'GET', url: requestUrl(input), body });
      headers.set('authorization', signed.authorization);
      headers.set('x-huudis-date', signed['x-huudis-date']);
    }
    return baseFetch(input, { ...init, headers });
  }) as typeof fetch;
}

/** A fetch that authenticates as an OIDC client (HTTP Basic client_id:client_secret). */
export function clientCredentialsFetch(creds: ClientCredentials, baseFetch: typeof fetch = fetch): typeof fetch {
  const basic = `Basic ${Buffer.from(`${creds.clientId}:${creds.clientSecret}`).toString('base64')}`;
  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    headers.set('authorization', basic);
    return baseFetch(input, { ...init, headers });
  }) as typeof fetch;
}
