# Changelog

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
