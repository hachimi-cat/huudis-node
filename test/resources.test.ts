import { describe, it, expect } from 'vitest';
import { HuudisClient } from '../src/index.js';

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function makeClient() {
  const captured: Captured[] = [];
  const fetchImpl: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    captured.push({
      url: typeof input === 'string' ? input : input.toString(),
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
    return new Response(
      JSON.stringify({
        data: { ok: true },
        error: null,
        meta: { requestId: 'req_test', timestamp: new Date().toISOString() },
      }),
      { headers: { 'content-type': 'application/json' } },
    );
  }) as typeof fetch;

  const client = new HuudisClient({
    issuer: 'https://huudis.test',
    clientId: 'huudis-cli',
    fetchImpl,
  });
  return { client, captured };
}

describe('HuudisClient resources', () => {
  it('iam.listUsers hits /api/v1/iam/users with query', async () => {
    const { client, captured } = makeClient();
    await client.iam.listUsers({ authToken: 't', query: { limit: 25 } });
    const c = captured[0]!;
    expect(c.method).toBe('GET');
    expect(c.url).toContain('/api/v1/iam/users');
    expect(c.url).toContain('limit=25');
    expect(c.headers.authorization).toBe('Bearer t');
  });

  it('iam.createAccessKey POSTs to /api/v1/iam/access-keys', async () => {
    const { client, captured } = makeClient();
    await client.iam.createAccessKey({ principalArn: 'forjio:huudis::acc_1:user/u1' }, { authToken: 't' });
    const c = captured[0]!;
    expect(c.method).toBe('POST');
    expect(c.url).toContain('/api/v1/iam/access-keys');
    expect(JSON.parse(c.body!)).toEqual({ principalArn: 'forjio:huudis::acc_1:user/u1' });
  });

  it('iam.revokeAccessKey POSTs to /access-keys/:id/revoke', async () => {
    const { client, captured } = makeClient();
    await client.iam.revokeAccessKey('ak_1', { authToken: 't' });
    expect(captured[0]!.method).toBe('POST');
    expect(captured[0]!.url).toContain('/api/v1/iam/access-keys/ak_1/revoke');
  });

  it('workspaces.switch POSTs to /workspaces/:id/switch', async () => {
    const { client, captured } = makeClient();
    await client.workspaces.switch('ws_1', { authToken: 't' });
    expect(captured[0]!.url).toContain('/api/v1/account/workspaces/ws_1/switch');
    expect(captured[0]!.method).toBe('POST');
  });

  it('endUsers.disable sends body', async () => {
    const { client, captured } = makeClient();
    await client.endUsers.disable('eu_1', { reason: 'fraud' }, { authToken: 't' });
    expect(captured[0]!.url).toContain('/api/v1/ops/end-users/eu_1/disable');
    expect(JSON.parse(captured[0]!.body!)).toEqual({ reason: 'fraud' });
  });

  it('mfa.deleteDevice DELETEs /mfa/devices/:id', async () => {
    const { client, captured } = makeClient();
    await client.mfa.deleteDevice('dev_1', { authToken: 't' });
    expect(captured[0]!.method).toBe('DELETE');
    expect(captured[0]!.url).toContain('/api/v1/mfa/devices/dev_1');
  });

  it('webhookSubscriptions.rotateSecret POSTs', async () => {
    const { client, captured } = makeClient();
    await client.webhookSubscriptions.rotateSecret('ws_1', { authToken: 't' });
    expect(captured[0]!.url).toContain('/api/v1/account/webhook-subscriptions/ws_1/rotate-secret');
    expect(captured[0]!.method).toBe('POST');
  });

  it('webhookSubscriptions.listDeliveries threads status query', async () => {
    const { client, captured } = makeClient();
    await client.webhookSubscriptions.listDeliveries('ws_1', { authToken: 't', query: { status: 'failed', limit: 10 } });
    const u = new URL(captured[0]!.url);
    expect(u.searchParams.get('status')).toBe('failed');
    expect(u.searchParams.get('limit')).toBe('10');
  });

  it('billing.plans GETs /billing/plans', async () => {
    const { client, captured } = makeClient();
    await client.billing.plans({ authToken: 't' });
    expect(captured[0]!.url).toContain('/api/v1/account/billing/plans');
  });

  it('account.sessions.revokeAll POSTs', async () => {
    const { client, captured } = makeClient();
    await client.account.sessions.revokeAll({ authToken: 't' });
    expect(captured[0]!.url).toContain('/api/v1/account/sessions/revoke-all');
    expect(captured[0]!.method).toBe('POST');
  });

  it('account.linked.unlink DELETEs /linked-accounts/:provider', async () => {
    const { client, captured } = makeClient();
    await client.account.linked.unlink('google', { authToken: 't' });
    expect(captured[0]!.method).toBe('DELETE');
    expect(captured[0]!.url).toContain('/api/v1/account/linked-accounts/google');
  });

  it('connectedApps.revoke DELETEs', async () => {
    const { client, captured } = makeClient();
    await client.connectedApps.revoke('app_1', { authToken: 't' });
    expect(captured[0]!.method).toBe('DELETE');
    expect(captured[0]!.url).toContain('/api/v1/account/connected-apps/app_1');
  });

  it('identityProviders.create POSTs to /iam/identity-providers', async () => {
    const { client, captured } = makeClient();
    await client.identityProviders.create({ kind: 'oidc', name: 'Google Workspace' }, { authToken: 't' });
    expect(captured[0]!.method).toBe('POST');
    expect(captured[0]!.url).toContain('/api/v1/iam/identity-providers');
  });

  it('authz.check POSTs to /authz/check', async () => {
    const { client, captured } = makeClient();
    await client.authz.check(
      {
        principal: { type: 'user', id: 'u1', accountId: 'acc_1' },
        action: 'huudis:iam:ListUsers',
        resource: 'forjio:huudis::acc_1:*',
      },
      { authToken: 't' },
    );
    expect(captured[0]!.url).toContain('/api/v1/authz/check');
    expect(captured[0]!.method).toBe('POST');
  });

  it('does not attach auth header when neither session nor authToken provided', async () => {
    const { client, captured } = makeClient();
    await client.iam.listUsers();
    expect(captured[0]!.headers.authorization).toBeUndefined();
  });

  it('legacy authzCheck still works and forwards to /authz/check', async () => {
    const { client, captured } = makeClient();
    await client.authzCheck(
      { principal: { type: 'user', id: 'u', accountId: 'a' }, action: 'x', resource: 'y' },
      { accessToken: 'legacy-tok' },
    );
    expect(captured[0]!.url).toContain('/api/v1/authz/check');
    expect(captured[0]!.headers.authorization).toBe('Bearer legacy-tok');
  });
});
