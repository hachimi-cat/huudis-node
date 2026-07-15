/**
 * Resource namespaces for HuudisClient. Each builder takes an ApiClient
 * and returns an object of thin Promise-returning methods that map 1:1
 * to backend routes.
 *
 * Every method accepts an optional `{ authToken }` to override the
 * client-level bearer for a single call — primarily for CLIs that hold
 * tokens explicitly rather than via a Session.
 */

import type { ApiClient, RequestOptions } from '@forjio/sdk/http-client';
import type {
  AccountProfile,
  AssumedSession,
  AuditEntry,
  AuthzCheckInput,
  AuthzCheckResult,
  BillingInvoice,
  BillingPlan,
  BillingSubscription,
  BillingUsage,
  BrowserSession,
  CheckoutSession,
  ConnectedApp,
  EndUser,
  IamAccessKey,
  IamGroup,
  IamPolicy,
  IamPolicyAttachment,
  IamPrincipalType,
  IamRole,
  IamServiceAccount,
  IamUser,
  IamUserInvite,
  IdentityProvider,
  ImpersonationSession,
  LinkedAccount,
  MfaDevice,
  MfaEnrollment,
  OidcClient,
  RequestAuth,
  ServiceStatus,
  WebhookDelivery,
  WebhookEvent,
  WebhookSubscription,
  Workspace,
} from './types.js';

type Ro = RequestOptions;

function authRo(opts?: RequestAuth): Ro {
  return opts?.authToken ? { authToken: opts.authToken } : {};
}

function authRoWithQuery(opts: (RequestAuth & { query?: Record<string, unknown> }) | undefined): Ro {
  const ro: Ro = {};
  if (opts?.authToken) ro.authToken = opts.authToken;
  if (opts?.query) ro.query = opts.query as Record<string, string | number | boolean | undefined>;
  return ro;
}

export function buildResources(api: ApiClient) {
  return {
    // ==========================================================================
    // IAM
    // ==========================================================================
    iam: {
      // Users
      listUsers: (opts?: RequestAuth & { query?: { limit?: number; cursor?: string } }) =>
        api.get<{ items: IamUser[]; nextCursor?: string }>('/api/v1/iam/users', authRoWithQuery(opts)),
      createUser: (
        body: { email: string; name?: string; password?: string; role?: string },
        opts?: RequestAuth,
      ) => api.post<IamUser>('/api/v1/iam/users', body, authRo(opts)),
      updateUser: (id: string, body: Partial<IamUser>, opts?: RequestAuth) =>
        api.patch<IamUser>(`/api/v1/iam/users/${id}`, body, authRo(opts)),
      deleteUser: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/users/${id}`, authRo(opts)),
      resetUserPassword: (id: string, opts?: RequestAuth) =>
        api.post<{ sent: boolean }>(`/api/v1/iam/users/${id}/reset-password`, undefined, authRo(opts)),

      // Invites
      listInvites: (opts?: RequestAuth) =>
        api.get<IamUserInvite[]>('/api/v1/iam/invites', authRo(opts)),
      sendInvite: (body: { email: string; role?: string }, opts?: RequestAuth) =>
        api.post<IamUserInvite>('/api/v1/iam/invites', body, authRo(opts)),
      cancelInvite: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/invites/${id}`, authRo(opts)),

      // Access keys
      listAccessKeys: (opts?: RequestAuth & { query?: { principalArn?: string } }) =>
        api.get<IamAccessKey[]>('/api/v1/iam/access-keys', authRoWithQuery(opts)),
      createAccessKey: (body: { principalArn: string; description?: string }, opts?: RequestAuth) =>
        api.post<IamAccessKey>('/api/v1/iam/access-keys', body, authRo(opts)),
      revokeAccessKey: (id: string, opts?: RequestAuth) =>
        api.post<IamAccessKey>(`/api/v1/iam/access-keys/${id}/revoke`, undefined, authRo(opts)),
      deleteAccessKey: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/access-keys/${id}`, authRo(opts)),

      // Groups
      listGroups: (opts?: RequestAuth) => api.get<IamGroup[]>('/api/v1/iam/groups', authRo(opts)),
      getGroup: (id: string, opts?: RequestAuth) =>
        api.get<IamGroup>(`/api/v1/iam/groups/${id}`, authRo(opts)),
      createGroup: (body: { name: string; description?: string }, opts?: RequestAuth) =>
        api.post<IamGroup>('/api/v1/iam/groups', body, authRo(opts)),
      deleteGroup: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/groups/${id}`, authRo(opts)),
      addGroupMember: (id: string, userId: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/iam/groups/${id}/members`, { userId }, authRo(opts)),
      removeGroupMember: (id: string, userId: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/groups/${id}/members/${userId}`, authRo(opts)),

      // Roles
      listRoles: (opts?: RequestAuth) => api.get<IamRole[]>('/api/v1/iam/roles', authRo(opts)),
      getRole: (id: string, opts?: RequestAuth) =>
        api.get<IamRole>(`/api/v1/iam/roles/${id}`, authRo(opts)),
      createRole: (
        body: { name: string; description?: string; trustPolicy: Record<string, unknown> },
        opts?: RequestAuth,
      ) => api.post<IamRole>('/api/v1/iam/roles', body, authRo(opts)),
      deleteRole: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/roles/${id}`, authRo(opts)),

      // Service accounts
      listServiceAccounts: (opts?: RequestAuth) =>
        api.get<IamServiceAccount[]>('/api/v1/iam/service-accounts', authRo(opts)),
      getServiceAccount: (id: string, opts?: RequestAuth) =>
        api.get<IamServiceAccount>(`/api/v1/iam/service-accounts/${id}`, authRo(opts)),
      createServiceAccount: (body: { name: string; description?: string }, opts?: RequestAuth) =>
        api.post<IamServiceAccount>('/api/v1/iam/service-accounts', body, authRo(opts)),
      deleteServiceAccount: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/service-accounts/${id}`, authRo(opts)),

      // Policies
      listPolicies: (opts?: RequestAuth & { query?: { kind?: 'custom' | 'canned' } }) =>
        api.get<IamPolicy[]>('/api/v1/iam/policies', authRoWithQuery(opts)),
      getPolicy: (id: string, opts?: RequestAuth) =>
        api.get<IamPolicy>(`/api/v1/iam/policies/${id}`, authRo(opts)),
      createPolicy: (
        body: { name: string; document: Record<string, unknown>; description?: string },
        opts?: RequestAuth,
      ) => api.post<IamPolicy>('/api/v1/iam/policies', body, authRo(opts)),
      updatePolicy: (
        id: string,
        body: Partial<{ name: string; document: Record<string, unknown>; description: string }>,
        opts?: RequestAuth,
      ) => api.patch<IamPolicy>(`/api/v1/iam/policies/${id}`, body, authRo(opts)),
      deletePolicy: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/policies/${id}`, authRo(opts)),

      // Policy attachments
      listPolicyAttachments: (
        opts?: RequestAuth & {
          query?: { policyId?: string; principalArn?: string };
        },
      ) => api.get<IamPolicyAttachment[]>('/api/v1/iam/policy-attachments', authRoWithQuery(opts)),
      attachPolicy: (body: { policyId: string; principalArn: string }, opts?: RequestAuth) =>
        api.post<IamPolicyAttachment>('/api/v1/iam/policy-attachments', body, authRo(opts)),
      detachPolicy: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/policy-attachments/${id}`, authRo(opts)),
    },

    // ==========================================================================
    // Identity providers (separate router under /iam/identity-providers)
    // ==========================================================================
    identityProviders: {
      list: (opts?: RequestAuth) =>
        api.get<IdentityProvider[]>('/api/v1/iam/identity-providers', authRo(opts)),
      create: (
        body: { kind: IdentityProvider['kind']; name: string; metadata?: Record<string, unknown> },
        opts?: RequestAuth,
      ) => api.post<IdentityProvider>('/api/v1/iam/identity-providers', body, authRo(opts)),
      update: (id: string, body: Partial<IdentityProvider>, opts?: RequestAuth) =>
        api.patch<IdentityProvider>(`/api/v1/iam/identity-providers/${id}`, body, authRo(opts)),
      delete: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/iam/identity-providers/${id}`, authRo(opts)),
    },

    // ==========================================================================
    // Assumed sessions
    // ==========================================================================
    assumedSessions: {
      list: (opts?: RequestAuth & { query?: { activeOnly?: boolean } }) =>
        api.get<AssumedSession[]>('/api/v1/iam/assumed-sessions', authRoWithQuery(opts)),
      revoke: (id: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/iam/assumed-sessions/${id}/revoke`, undefined, authRo(opts)),
    },

    // ==========================================================================
    // Authz (extras beyond the legacy authzCheck method on the client)
    // ==========================================================================
    authz: {
      check: (input: AuthzCheckInput, opts?: RequestAuth) =>
        api.post<AuthzCheckResult>('/api/v1/authz/check', input, authRo(opts)),
      assumeRole: (
        body: { roleArn: string; sessionName?: string; durationSeconds?: number },
        opts?: RequestAuth,
      ) =>
        api.post<{ accessToken: string; expiresAt: string; sessionId: string }>(
          '/api/v1/authz/assume-role',
          body,
          authRo(opts),
        ),
      whoami: (opts?: RequestAuth) =>
        api.get<{ principal: string; accountId: string; scopes: string[] }>(
          '/api/v1/authz/whoami',
          authRo(opts),
        ),
    },

    // ==========================================================================
    // Workspaces
    // ==========================================================================
    workspaces: {
      list: (opts?: RequestAuth) =>
        api.get<Workspace[]>('/api/v1/account/workspaces', authRo(opts)),
      create: (body: { name: string; slug?: string }, opts?: RequestAuth) =>
        api.post<Workspace>('/api/v1/account/workspaces', body, authRo(opts)),
      update: (id: string, body: Partial<Workspace>, opts?: RequestAuth) =>
        api.patch<Workspace>(`/api/v1/account/workspaces/${id}`, body, authRo(opts)),
      switch: (id: string, opts?: RequestAuth) =>
        api.post<{ accessToken: string }>(
          `/api/v1/account/workspaces/${id}/switch`,
          undefined,
          authRo(opts),
        ),
    },

    // ==========================================================================
    // End-users (ops admin)
    // ==========================================================================
    endUsers: {
      list: (
        opts?: RequestAuth & { query?: { limit?: number; cursor?: string; search?: string } },
      ) =>
        api.get<{ items: EndUser[]; nextCursor?: string }>(
          '/api/v1/ops/end-users',
          authRoWithQuery(opts),
        ),
      get: (id: string, opts?: RequestAuth) =>
        api.get<EndUser>(`/api/v1/ops/end-users/${id}`, authRo(opts)),
      revoke: (id: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/${id}/revoke`, undefined, authRo(opts)),
      sendPasswordReset: (id: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/${id}/send-password-reset`, undefined, authRo(opts)),
      verifyEmail: (id: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/${id}/verify-email`, undefined, authRo(opts)),
      impersonate: (id: string, body?: { reason?: string }, opts?: RequestAuth) =>
        api.post<ImpersonationSession>(
          `/api/v1/ops/end-users/${id}/impersonate`,
          body,
          authRo(opts),
        ),
      stopImpersonation: (opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/stop-impersonation`, undefined, authRo(opts)),
      disable: (id: string, body?: { reason?: string }, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/${id}/disable`, body, authRo(opts)),
      enable: (id: string, opts?: RequestAuth) =>
        api.post<void>(`/api/v1/ops/end-users/${id}/enable`, undefined, authRo(opts)),
    },

    // ==========================================================================
    // MFA
    // ==========================================================================
    mfa: {
      enroll: (body: { type: MfaDevice['type']; label?: string }, opts?: RequestAuth) =>
        api.post<MfaEnrollment>('/api/v1/mfa/enroll', body, authRo(opts)),
      verifyEnrollment: (body: { deviceId: string; code: string }, opts?: RequestAuth) =>
        api.post<MfaDevice>('/api/v1/mfa/verify-enrollment', body, authRo(opts)),
      verifyLogin: (body: { code: string }, opts?: RequestAuth) =>
        api.post<{ accessToken: string }>('/api/v1/mfa/verify-login', body, authRo(opts)),
      listDevices: (opts?: RequestAuth) => api.get<MfaDevice[]>('/api/v1/mfa/devices', authRo(opts)),
      deleteDevice: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/mfa/devices/${id}`, authRo(opts)),
    },

    // ==========================================================================
    // OIDC clients
    // ==========================================================================
    oidcClients: {
      list: (opts?: RequestAuth) => api.get<OidcClient[]>('/api/v1/oidc/clients', authRo(opts)),
      create: (
        body: { name: string; redirectUris: string[]; scopes?: string[]; confidential?: boolean },
        opts?: RequestAuth,
      ) => api.post<OidcClient>('/api/v1/oidc/clients', body, authRo(opts)),
      update: (id: string, body: Partial<OidcClient>, opts?: RequestAuth) =>
        api.patch<OidcClient>(`/api/v1/oidc/clients/${id}`, body, authRo(opts)),
      rotateSecret: (id: string, opts?: RequestAuth) =>
        api.post<{ clientSecret: string }>(
          `/api/v1/oidc/clients/${id}/rotate-secret`,
          undefined,
          authRo(opts),
        ),
      delete: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/oidc/clients/${id}`, authRo(opts)),
    },

    // ==========================================================================
    // Consents / connected apps
    // ==========================================================================
    connectedApps: {
      list: (opts?: RequestAuth) =>
        api.get<ConnectedApp[]>('/api/v1/account/connected-apps', authRo(opts)),
      revoke: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/account/connected-apps/${id}`, authRo(opts)),
    },

    // ==========================================================================
    // Account services (Forjio product enablement)
    // ==========================================================================
    services: {
      list: (opts?: RequestAuth) =>
        api.get<ServiceStatus[]>('/api/v1/account/services', authRo(opts)),
      enable: (body: { service: string }, opts?: RequestAuth) =>
        api.post<ServiceStatus>('/api/v1/account/services/enable', body, authRo(opts)),
      disable: (body: { service: string }, opts?: RequestAuth) =>
        api.post<ServiceStatus>('/api/v1/account/services/disable', body, authRo(opts)),
    },

    // ==========================================================================
    // Webhook subscriptions
    // ==========================================================================
    webhookSubscriptions: {
      list: (opts?: RequestAuth) =>
        api.get<WebhookSubscription[]>('/api/v1/account/webhook-subscriptions', authRo(opts)),
      create: (
        body: { url: string; events: string[]; description?: string },
        opts?: RequestAuth,
      ) =>
        api.post<WebhookSubscription>(
          '/api/v1/account/webhook-subscriptions',
          body,
          authRo(opts),
        ),
      get: (id: string, opts?: RequestAuth) =>
        api.get<WebhookSubscription>(`/api/v1/account/webhook-subscriptions/${id}`, authRo(opts)),
      update: (
        id: string,
        body: Partial<{ url: string; events: string[]; description: string; active: boolean }>,
        opts?: RequestAuth,
      ) =>
        api.patch<WebhookSubscription>(
          `/api/v1/account/webhook-subscriptions/${id}`,
          body,
          authRo(opts),
        ),
      delete: (id: string, opts?: RequestAuth) =>
        api.delete<void>(`/api/v1/account/webhook-subscriptions/${id}`, authRo(opts)),
      rotateSecret: (id: string, opts?: RequestAuth) =>
        api.post<{ secret: string }>(
          `/api/v1/account/webhook-subscriptions/${id}/rotate-secret`,
          undefined,
          authRo(opts),
        ),
      listDeliveries: (
        id: string,
        opts?: RequestAuth & { query?: { status?: WebhookDelivery['status']; limit?: number } },
      ) =>
        api.get<WebhookDelivery[]>(
          `/api/v1/account/webhook-subscriptions/${id}/deliveries`,
          authRoWithQuery(opts),
        ),
      replayDelivery: (deliveryId: string, opts?: RequestAuth) =>
        api.post<void>(
          `/api/v1/account/webhook-subscriptions/deliveries/${deliveryId}/replay`,
          undefined,
          authRo(opts),
        ),
      eventsCatalog: (opts?: RequestAuth) =>
        api.get<WebhookEvent[]>('/api/v1/account/webhook-subscriptions/events/catalog', authRo(opts)),
    },

    // ==========================================================================
    // Billing
    // ==========================================================================
    billing: {
      summary: (opts?: RequestAuth) =>
        api.get<{ subscription?: BillingSubscription; usage: BillingUsage }>(
          '/api/v1/account/billing',
          authRo(opts),
        ),
      plans: (opts?: RequestAuth) =>
        api.get<BillingPlan[]>('/api/v1/account/billing/plans', authRo(opts)),
      usage: (opts?: RequestAuth) =>
        api.get<BillingUsage>('/api/v1/account/billing/usage', authRo(opts)),
      invoices: (opts?: RequestAuth & { query?: { limit?: number } }) =>
        api.get<BillingInvoice[]>('/api/v1/account/billing/invoices', authRoWithQuery(opts)),
      checkout: (
        body: { planId: string; successUrl?: string; cancelUrl?: string },
        opts?: RequestAuth,
      ) => api.post<CheckoutSession>('/api/v1/account/billing/checkout', body, authRo(opts)),
      cancel: (opts?: RequestAuth) =>
        api.post<BillingSubscription>('/api/v1/account/billing/cancel', undefined, authRo(opts)),
    },

    // ==========================================================================
    // Account profile / sessions / linked / audit
    // ==========================================================================
    account: {
      get: (opts?: RequestAuth) => api.get<AccountProfile>('/api/v1/account', authRo(opts)),
      update: (body: Partial<AccountProfile>, opts?: RequestAuth) =>
        api.patch<AccountProfile>('/api/v1/account', body, authRo(opts)),
      changeEmail: (body: { newEmail: string; password: string }, opts?: RequestAuth) =>
        api.post<{ pendingVerification: boolean }>(
          '/api/v1/account/email-change',
          body,
          authRo(opts),
        ),
      changePassword: (
        body: { currentPassword: string; newPassword: string },
        opts?: RequestAuth,
      ) => api.post<void>('/api/v1/account/password-change', body, authRo(opts)),
      audit: (opts?: RequestAuth & { query?: { eventType?: string; since?: string; limit?: number } }) =>
        api.get<AuditEntry[]>('/api/v1/account/audit', authRoWithQuery(opts)),
      sessions: {
        list: (opts?: RequestAuth) =>
          api.get<BrowserSession[]>('/api/v1/account/sessions', authRo(opts)),
        revoke: (id: string, opts?: RequestAuth) =>
          api.post<void>(`/api/v1/account/sessions/${id}/revoke`, undefined, authRo(opts)),
        revokeAll: (opts?: RequestAuth) =>
          api.post<{ revoked: number }>(
            '/api/v1/account/sessions/revoke-all',
            undefined,
            authRo(opts),
          ),
      },
      linked: {
        list: (opts?: RequestAuth) =>
          api.get<LinkedAccount[]>('/api/v1/account/linked-accounts', authRo(opts)),
        unlink: (provider: string, opts?: RequestAuth) =>
          api.delete<void>(`/api/v1/account/linked-accounts/${provider}`, authRo(opts)),
      },
    },
  };
}

export type HuudisResources = ReturnType<typeof buildResources>;
/** Keep IamPrincipalType referenced (exported for downstream consumers). */
export type { IamPrincipalType };
