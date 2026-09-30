import { describe, it, expect } from 'vitest';
import { HuudisClient, type Session } from '../src/index.js';

// client.api: every feature route, generated from the API spec (scripts/apigen.sh).
describe('client.api (generated from the spec)', () => {
  function capture() {
    const seen: Array<{ url: string; method: string; body?: string; auth?: string | null }> = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push({
        url: typeof input === 'string' ? input : input.toString(),
        method: init?.method ?? 'GET',
        body: typeof init?.body === 'string' ? init.body : undefined,
        auth: new Headers(init?.headers).get('authorization'),
      });
      return new Response(JSON.stringify({ data: { ok: true }, error: null, meta: { requestId: 'r', timestamp: '' } }), {
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    // A signed-in session: what ApiClient reads from one (the bearer, and whether to refresh).
    const session = {
      data: { accessToken: 'tok_live', expiresAt: Math.floor(Date.now() / 1000) + 3600, issuer: 'https://huudis.test', clientId: 'huudis-cli' },
      willExpireSoon: () => false,
      refresh: async () => {},
    } as unknown as Session;
    const client = new HuudisClient({ issuer: 'https://huudis.test', clientId: 'huudis-cli', fetchImpl, session });
    return { client, seen };
  }

  it('creates an IAM user with the fields Huudis validates, carrying the session bearer', async () => {
    const { client, seen } = capture();
    await client.api.iamCreateUsers({ email: 'rina@example.com', role: 'member', sendInviteEmail: false });
    expect(seen[0]!.method).toBe('POST');
    expect(seen[0]!.url).toBe('https://huudis.test/api/v1/iam/users');
    expect(JSON.parse(seen[0]!.body!)).toEqual({ email: 'rina@example.com', role: 'member', sendInviteEmail: false });
    expect(seen[0]!.auth).toBe('Bearer tok_live');
  });

  it('puts path parameters in the path and query fields in the query', async () => {
    const { client, seen } = capture();
    await client.api.iamDeleteGroupsMembers('grp 1', 'usr/2');
    await client.api.accountAudit({ limit: 5, outcome: 'denied' });
    expect(seen[0]!.method).toBe('DELETE');
    expect(seen[0]!.url).toBe('https://huudis.test/api/v1/iam/groups/grp%201/members/usr%2F2');
    const listed = new URL(seen[1]!.url);
    expect(listed.pathname).toBe('/api/v1/account/audit');
    expect(Object.fromEntries(listed.searchParams)).toEqual({ limit: '5', outcome: 'denied' });
  });

  it('sends the body of a DELETE that takes one (account deletion needs the password)', async () => {
    const { client, seen } = capture();
    await client.api.accountDelete({ password: 'pw' });
    expect(seen[0]!.method).toBe('DELETE');
    expect(seen[0]!.url).toBe('https://huudis.test/api/v1/account');
    expect(JSON.parse(seen[0]!.body!)).toEqual({ password: 'pw' });
  });

  it('has a method for every feature route', () => {
    const { client } = capture();
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(client.api)).filter((n) => n !== 'constructor' && n !== 'call');
    expect(methods.length).toBeGreaterThan(105);
  });
});
