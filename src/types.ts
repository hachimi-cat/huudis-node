/* eslint-disable @typescript-eslint/no-explicit-any */

// =============================================================================
// OIDC + Auth (kept from v0.3.0)
// =============================================================================

export interface HuudisClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  iat: number;
  jti?: string;

  /** Forjio-specific fields — always present on a Huudis-issued token. */
  accountId: string;
  identityId: string;
  identityType: 'user' | 'service_account';
  scope: string;
  mfaVerified?: boolean;
  sessionId?: string;

  /** Standard OIDC profile fields when scope includes them. */
  email?: string;
  email_verified?: boolean;
  name?: string;
  locale?: string;
}

export interface AuthzCheckInput {
  principal: {
    type: 'user' | 'group' | 'role' | 'service_account';
    id: string;
    accountId: string;
    mfaVerified?: boolean;
  };
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}

export interface AuthzCheckResult {
  decision: 'Allow' | 'Deny' | 'ImplicitDeny';
  allow: boolean;
  reason?: string;
  matchedSid?: string;
}

export interface AuthorizationUrlOptions {
  redirectUri: string;
  scope?: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
  loginHint?: string;
  idpHint?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

export interface UserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  locale?: string;
  [k: string]: unknown;
}

// =============================================================================
// Common
// =============================================================================

export interface RequestAuth {
  /** Override the client-level session bearer with an explicit token. */
  authToken?: string;
}

export interface ListPage<T> {
  items: T[];
  nextCursor?: string;
}

export type Iso8601 = string;

// =============================================================================
// IAM
// =============================================================================

export type IamPrincipalType = 'user' | 'group' | 'role' | 'service_account';

export interface IamUser {
  id: string;
  accountId: string;
  email: string;
  name?: string;
  emailVerified: boolean;
  mfaEnrolled: boolean;
  disabled: boolean;
  createdAt: Iso8601;
}

export interface IamUserInvite {
  id: string;
  accountId: string;
  email: string;
  role?: string;
  status: 'pending' | 'accepted' | 'cancelled' | 'expired';
  expiresAt: Iso8601;
  createdAt: Iso8601;
}

export interface IamAccessKey {
  id: string;
  accountId: string;
  principalArn: string;
  description?: string;
  status: 'active' | 'revoked';
  secretAccessKey?: string;
  createdAt: Iso8601;
  lastUsedAt?: Iso8601;
}

export interface IamGroup {
  id: string;
  accountId: string;
  name: string;
  description?: string;
  memberCount?: number;
  createdAt: Iso8601;
}

export interface IamRole {
  id: string;
  accountId: string;
  name: string;
  description?: string;
  trustPolicy?: Record<string, unknown>;
  createdAt: Iso8601;
}

export interface IamServiceAccount {
  id: string;
  accountId: string;
  name: string;
  description?: string;
  createdAt: Iso8601;
}

export interface IamPolicy {
  id: string;
  accountId: string;
  name: string;
  description?: string;
  document: Record<string, unknown>;
  builtIn?: boolean;
  createdAt: Iso8601;
  updatedAt: Iso8601;
}

export interface IamPolicyAttachment {
  id: string;
  accountId: string;
  policyId: string;
  principalArn: string;
  createdAt: Iso8601;
}

// =============================================================================
// Workspaces / Members
// =============================================================================

export interface Workspace {
  id: string;
  name: string;
  slug?: string;
  ownerId: string;
  role?: 'owner' | 'admin' | 'member' | 'viewer';
  createdAt: Iso8601;
}

// =============================================================================
// End-users (ops)
// =============================================================================

export interface EndUser {
  id: string;
  accountId: string;
  email: string;
  name?: string;
  emailVerified: boolean;
  disabled: boolean;
  createdAt: Iso8601;
  lastLoginAt?: Iso8601;
}

export interface ImpersonationSession {
  sessionId: string;
  accessToken: string;
  expiresAt: Iso8601;
}

// =============================================================================
// MFA
// =============================================================================

export interface MfaDevice {
  id: string;
  type: 'totp' | 'webauthn' | 'sms';
  label?: string;
  createdAt: Iso8601;
  lastUsedAt?: Iso8601;
}

export interface MfaEnrollment {
  deviceId: string;
  secret?: string;
  otpAuthUrl?: string;
  qrCodePng?: string;
}

// =============================================================================
// OIDC clients
// =============================================================================

export interface OidcClient {
  id: string;
  accountId: string;
  name: string;
  redirectUris: string[];
  scopes: string[];
  clientSecret?: string;
  confidential: boolean;
  createdAt: Iso8601;
  updatedAt: Iso8601;
}

// =============================================================================
// Identity providers
// =============================================================================

export interface IdentityProvider {
  id: string;
  accountId: string;
  kind: 'oidc' | 'saml' | 'social';
  name: string;
  enabled: boolean;
  metadata?: Record<string, unknown>;
  createdAt: Iso8601;
}

// =============================================================================
// Assumed sessions
// =============================================================================

export interface AssumedSession {
  id: string;
  accountId: string;
  callerArn: string;
  roleArn: string;
  expiresAt: Iso8601;
  active: boolean;
  createdAt: Iso8601;
}

// =============================================================================
// Webhook subscriptions
// =============================================================================

export interface WebhookSubscription {
  id: string;
  accountId: string;
  url: string;
  events: string[];
  description?: string;
  active: boolean;
  secret?: string;
  createdAt: Iso8601;
  updatedAt: Iso8601;
}

export interface WebhookDelivery {
  id: string;
  subscriptionId: string;
  eventId: string;
  eventType: string;
  status: 'pending' | 'success' | 'failed';
  httpStatus?: number;
  responseBody?: string;
  attemptCount: number;
  lastAttemptAt?: Iso8601;
  createdAt: Iso8601;
}

export interface WebhookEvent {
  type: string;
  description?: string;
  payloadSchema?: Record<string, unknown>;
}

// =============================================================================
// Billing
// =============================================================================

export interface BillingPlan {
  id: string;
  name: string;
  amount: number;
  currency: string;
  interval: 'month' | 'year';
  features?: string[];
}

export interface BillingSubscription {
  id: string;
  planId: string;
  status: string;
  currentPeriodEnd: Iso8601;
}

export interface BillingUsage {
  identities: number;
  authzChecks: number;
  webhookDeliveries: number;
  asOf: Iso8601;
}

export interface BillingInvoice {
  id: string;
  amount: number;
  currency: string;
  status: string;
  hostedInvoiceUrl?: string;
  createdAt: Iso8601;
}

export interface CheckoutSession {
  url: string;
  sessionId: string;
}

// =============================================================================
// Account / sessions / linked / audit
// =============================================================================

export interface AccountProfile {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  locale?: string;
  mfaEnrolled: boolean;
  createdAt: Iso8601;
}

export interface BrowserSession {
  id: string;
  userAgent?: string;
  ipAddress?: string;
  createdAt: Iso8601;
  lastSeenAt: Iso8601;
  current?: boolean;
}

export interface LinkedAccount {
  provider: string;
  subject: string;
  email?: string;
  linkedAt: Iso8601;
}

export interface AuditEntry {
  id: string;
  accountId: string;
  actor: string;
  action: string;
  resource?: string;
  outcome: 'success' | 'failure';
  details?: Record<string, unknown>;
  timestamp: Iso8601;
}

// =============================================================================
// Connected apps (consents)
// =============================================================================

export interface ConnectedApp {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  consentedAt: Iso8601;
  lastUsedAt?: Iso8601;
}

// =============================================================================
// Services (Forjio products opt-in)
// =============================================================================

export interface ServiceStatus {
  service: string;
  enabled: boolean;
  enabledAt?: Iso8601;
}
