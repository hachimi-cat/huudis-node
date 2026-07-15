/**
 * @huudis/node — Official Node.js SDK for Huudis.
 *
 * Two entry styles:
 *   1. Module-level convenience:  `verifyAccessToken(tokenOrHeader)` reads
 *      `HUUDIS_ISSUER` + `HUUDIS_AUDIENCE` from env. Fits the "three-line
 *      middleware" example on the landing page.
 *   2. Explicit client:           `new HuudisClient({ issuer, clientId,
 *      clientSecret, audience })` for the full surface — OIDC code flow,
 *      refresh, userinfo, /authz/check.
 */

export { HuudisClient } from './client.js';
export { verifyAccessToken, HuudisAuthError } from './auth.js';
export { verifyWebhookSignature } from './webhooks.js';
export type { VerifyOptions } from './webhooks.js';
export * from './types.js';
export type { HuudisResources } from './resources.js';
// Re-export CLI harness for convenience — consumers can construct their own
// Session / ApiClient against @forjio/sdk directly, or import them here.
export {
  Session,
  ApiClient,
  ApiError,
  NetworkError,
  RefreshError,
  startDeviceFlow,
  pollDeviceToken,
  refreshAccessToken,
  fetchDiscovery,
} from '@forjio/sdk';
export type { DeviceFlowStart, DeviceTokens, DiscoveryDocument } from '@forjio/sdk';
