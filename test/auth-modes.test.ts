import { createHash, createHmac } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { HuudisClient, signRequest, type Session } from '../src/index.js';

// Each route group takes its own credential: the session bearer, an IAM access key
// (Huudis-HMAC-SHA256) for programs, the OIDC client credentials for /api/v1/app/*.

const KEY = { accessKeyId: 'AKIA0123456789ABCDEF01234567', secretAccessKey: 'c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTAxMjM=' };

interface Seen { url: string; method: string; body?: string; headers: Headers }

function capture() {
  const seen: Seen[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push({
      url: typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url,
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? init.body : undefined,
      headers: new Headers(init?.headers),
    });
    return new Response(JSON.stringify({ data: { ok: true }, error: null, meta: { requestId: 'r', timestamp: '' } }), {
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { seen, fetchImpl };
}

const session = {
  data: { accessToken: 'tok_live', expiresAt: Math.floor(Date.now() / 1000) + 3600, issuer: 'https://huudis.test', clientId: 'huudis-cli' },
  willExpireSoon: () => false,
  refresh: async () => {},
} as unknown as Session;

/** What the Huudis server computes (backend/src/services/iam-access-keys.ts), restated. */
function expectedSignature(secret: string, method: string, pathWithQuery: string, date: string, body = ''): string {
  const bodyHash = createHash('sha256').update(body).digest('hex');
  return createHmac('sha256', secret).update(`${method}\n${pathWithQuery}\n${date}\n${bodyHash}`).digest('hex');
}

function parseAuth(h: string | null) {
  const m = /^Huudis-HMAC-SHA256 Credential=([A-Z0-9]+), Signature=([a-f0-9]{64})$/.exec(h ?? '');
  expect(m, `authorization header: ${h}`).not.toBeNull();
  return { credential: m![1], signature: m![2] };
}

afterEach(() => {
  delete process.env.HUUDIS_ACCESS_KEY_ID;
  delete process.env.HUUDIS_SECRET_ACCESS_KEY;
  delete process.env.HUUDIS_WORKSPACE_ID;
});

describe('access key (Huudis-HMAC-SHA256)', () => {
  it('signs a GET: method, path with query, X-Huudis-Date, empty body', async () => {
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', accessKey: KEY, fetchImpl });
    await client.api.accountAudit({ limit: 5, outcome: 'denied' });
    const req = seen[0]!;
    const url = new URL(req.url);
    const date = req.headers.get('x-huudis-date')!;
    expect(Math.abs(Date.parse(date) - Date.now())).toBeLessThan(60_000);
    const { credential, signature } = parseAuth(req.headers.get('authorization'));
    expect(credential).toBe(KEY.accessKeyId);
    expect(url.search).toBe('?limit=5&outcome=denied');
    expect(signature).toBe(expectedSignature(KEY.secretAccessKey, 'GET', `${url.pathname}${url.search}`, date));
  });

  it('signs the exact body bytes of a write', async () => {
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', accessKey: KEY, fetchImpl });
    await client.api.iamCreateGroups({ name: 'Ops', description: 'on call' });
    const req = seen[0]!;
    expect(req.method).toBe('POST');
    expect(JSON.parse(req.body!)).toEqual({ name: 'Ops', description: 'on call' });
    const date = req.headers.get('x-huudis-date')!;
    expect(parseAuth(req.headers.get('authorization')).signature)
      .toBe(expectedSignature(KEY.secretAccessKey, 'POST', '/api/v1/iam/groups', date, req.body));
  });

  it('signs the resource namespaces too, and reads the key from the environment', async () => {
    process.env.HUUDIS_ACCESS_KEY_ID = KEY.accessKeyId;
    process.env.HUUDIS_SECRET_ACCESS_KEY = KEY.secretAccessKey;
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', fetchImpl });
    await client.iam.listUsers();
    expect(parseAuth(seen[0]!.headers.get('authorization')).credential).toBe(KEY.accessKeyId);
  });

  it('names the workspace to act in', async () => {
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', accessKey: KEY, workspaceId: 'acc_123', fetchImpl });
    await client.api.iamUsers();
    expect(seen[0]!.headers.get('x-huudis-workspace-id')).toBe('acc_123');
  });

  it('a signed-in session wins over the key; a per-call token is sent as it is', async () => {
    const { seen, fetchImpl } = capture();
    const withSession = new HuudisClient({ issuer: 'https://huudis.test', clientId: 'c', session, accessKey: KEY, fetchImpl });
    await withSession.api.iamUsers();
    expect(seen[0]!.headers.get('authorization')).toBe('Bearer tok_live');

    const keyOnly = new HuudisClient({ issuer: 'https://huudis.test', accessKey: KEY, fetchImpl });
    await keyOnly.iam.listUsers({ authToken: 'tok_other' });
    expect(seen[1]!.headers.get('authorization')).toBe('Bearer tok_other');
  });

  it('signRequest is the same algorithm, for callers building their own requests', () => {
    const date = new Date('2026-09-30T12:00:00.000Z');
    const h = signRequest(KEY, { method: 'post', url: 'https://huudis.com/api/v1/authz/check?x=1', body: '{"a":1}', date });
    expect(h['x-huudis-date']).toBe('2026-09-30T12:00:00.000Z');
    expect(parseAuth(h.authorization).signature)
      .toBe(expectedSignature(KEY.secretAccessKey, 'POST', '/api/v1/authz/check?x=1', '2026-09-30T12:00:00.000Z', '{"a":1}'));
  });
});

describe('client credentials (/api/v1/app/*)', () => {
  it('sends the app\'s client_id:client_secret on /api/v1/app/*, even with a session', async () => {
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', clientId: 'oc_app', clientSecret: 's3cret', session, fetchImpl });
    await client.api.appUsers({ status: 'active' });
    await client.api.iamUsers();
    expect(seen[0]!.url).toBe('https://huudis.test/api/v1/app/users?status=active');
    expect(seen[0]!.headers.get('authorization')).toBe(`Basic ${Buffer.from('oc_app:s3cret').toString('base64')}`);
    expect(seen[1]!.headers.get('authorization')).toBe('Bearer tok_live');
  });

  it('says what is missing when the client has no secret', async () => {
    const { seen, fetchImpl } = capture();
    const client = new HuudisClient({ issuer: 'https://huudis.test', clientId: 'oc_app', session, fetchImpl });
    await expect(client.api.appUsers()).rejects.toMatchObject({ code: 'MISSING_CLIENT_CREDENTIALS' });
    expect(seen).toHaveLength(0);
  });
});

describe('construction', () => {
  it('needs a client id or an access key', () => {
    expect(() => new HuudisClient({ issuer: 'https://huudis.test' })).toThrow(/HUUDIS_CLIENT_ID/);
    const client = new HuudisClient({ issuer: 'https://huudis.test', accessKey: KEY });
    expect(() => client.authorizationUrl({ redirectUri: 'https://x', state: 's' })).toThrow(/HUUDIS_CLIENT_ID/);
  });
});
