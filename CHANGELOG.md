# Changelog

## 0.8.0
- New: `client.api.iamKeyRequests`, `iamGetKeyRequests`, `iamKeyRequestsChallenge`, `iamKeyRequestsApprove`, `iamKeyRequestsDeny` (what access keys ask a workspace owner to approve) and `iamKeyActions`, `iamKeyActionsUndo` (what keys did to the workspace's members, and undoing it).
- An access key can now add, invite, re-role and remove members, reset another member's password and manage SSO identity providers, when its user's policy names the action itself (`huudis:AddMember`, `huudis:InviteMember`, `huudis:UpdateMember`, `huudis:RemoveMember`, `huudis:ResetMemberPassword`, `huudis:CreateIdentityProvider`, `huudis:UpdateIdentityProvider`, `huudis:DeleteIdentityProvider`; a wildcard such as `huudis:*` does not grant them). Member changes run at once and every workspace owner is emailed a link to undo them. SSO, password resets and anything about the owner role answer `{ approvalRequired: true, request }` (HTTP 202) until an owner approves with a second-factor code; then the same call runs once. A key never sets or sees a member's password.

## 0.7.0
- `client.api.opsEndUsersImpersonate(id, { durationSeconds, reason })` takes `reason`, and `endUsers.impersonate(id, { reason })` now reaches the server (it was ignored): the audit log and the `huudis.ops.impersonation_*` webhook events carry it.
- Huudis now delivers every webhook event its catalog lists (they were reserved): verify them with `verifyWebhookSignature` as before; see /docs/api/webhooks for who receives which.

## 0.6.0
- A route read by id next to its list is named `get` + the list's name: `client.api.accountGetWebhookSubscriptions` (was `client.api.accountWebhookSubscriptions2`), `client.api.iamGetGroups` (was `client.api.iamGroups2`), `client.api.iamGetPolicies` (was `client.api.iamPolicies2`), `client.api.iamGetRoles` (was `client.api.iamRoles2`), `client.api.iamGetServiceAccounts` (was `client.api.iamServiceAccounts2`), `client.api.opsGetEndUsers` (was `client.api.opsEndUsers2`). Each old name stays as a deprecated alias.

## 0.5.0
- Access keys: `accessKey: { accessKeyId, secretAccessKey }` (or `HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY`) signs every call `Huudis-HMAC-SHA256` when there is no `session` — the key acts as its user on `/account/*`, `/iam/*`, `/authz/*` within the user's IAM policies. `clientId` is optional with a key.
- `client.api` sends `/api/v1/app/*` with the OIDC client credentials (`clientId` + `clientSecret`, HTTP Basic) instead of the session bearer, which those routes refuse.
- `workspaceId` (`HUUDIS_WORKSPACE_ID`) sends `X-Huudis-Workspace-Id`.
- New exports: `signRequest`, `accessKeyFetch`, `clientCredentialsFetch`.

## 0.4.2
- `client.api`: every feature route of the Huudis API, one method each (`client.api.<area><Action>(...)`), generated from the API spec; calls carry the client's `session` bearer like the resource namespaces. `GeneratedApi` is exported.

## 0.4.1
- Package metadata now points at the public mirror repo (github.com/hachimi-cat/huudis-node).

## 0.4.0
- Prior release.
