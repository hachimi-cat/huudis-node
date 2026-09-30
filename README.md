# @forjio/huudis-node

Official Node.js SDK for [Huudis](https://huudis.com). Verify access tokens,
run the OIDC authorization-code flow, and call `/authz/check` with a couple
of lines of code.

## Install

```bash
npm install @forjio/huudis-node
```

## Quickstart

Set these env vars (or pass them to the client):

```bash
HUUDIS_ISSUER=https://huudis.com
HUUDIS_AUDIENCE=oc_your_client_id   # or your HUUDIS_CLIENT_ID
HUUDIS_CLIENT_ID=oc_your_client_id
HUUDIS_CLIENT_SECRET=cs_...         # omit for public clients using PKCE
```

### Verify an access token

```ts
import { verifyAccessToken } from '@forjio/huudis-node';

app.get('/me', async (req, res) => {
  try {
    const claims = await verifyAccessToken(req.headers.authorization);
    res.json({ userId: claims.sub, email: claims.email });
  } catch (e) {
    res.status(401).json({ error: (e as Error).message });
  }
});
```

### OIDC sign-in flow

```ts
import { HuudisClient } from '@forjio/huudis-node';

const huudis = new HuudisClient();

// Step 1: redirect the user to Huudis
app.get('/login', (req, res) => {
  const url = huudis.authorizationUrl({
    redirectUri: 'https://yourapp.com/callback',
    state: generateState(req),
    codeChallenge: generatePkce(req),
  });
  res.redirect(url);
});

// Step 2: exchange the code, set a session
app.get('/callback', async (req, res) => {
  const tokens = await huudis.exchangeCode({
    code: String(req.query.code),
    redirectUri: 'https://yourapp.com/callback',
    codeVerifier: retrievePkce(req),
  });
  const userinfo = await huudis.userInfo(tokens.access_token);
  // ...set your own session cookie using userinfo.sub, etc.
  res.redirect('/dashboard');
});
```

### Authorization check

```ts
const result = await huudis.authzCheck(
  {
    principal: { type: 'user', id: claims.sub, accountId: claims.accountId },
    action: 'plugipay:DeleteInvoice',
    resource: 'forjio:plugipay::acc_.../invoice/inv_9F8',
  },
  { accessToken: req.headers.authorization.replace(/^Bearer\s+/i, '') },
);

if (!result.allow) {
  return res.status(403).json({ error: result.reason });
}
```

## Call the API — every route, with the right credential

`client.api` has one method per Huudis API route (generated from the API spec). Each call
carries the credential its route group takes:

| Routes | Credential | Client options |
|---|---|---|
| Everything a signed-in person may call | The person's bearer token | `session` (e.g. from the device flow) |
| `/account/*`, `/iam/*`, `/authz/*` for programs | An IAM access key, each request signed `Huudis-HMAC-SHA256`; acts as the key's user within the user's IAM policies | `accessKey: { accessKeyId, secretAccessKey }` or `HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY` |
| `/app/*` | Your OIDC app's client credentials (HTTP Basic) | `clientId` + `clientSecret` or `HUUDIS_CLIENT_ID` + `HUUDIS_CLIENT_SECRET` |

```ts
import { HuudisClient } from '@forjio/huudis-node';

// A program with an access key (no client id needed):
const huudis = new HuudisClient({
  issuer: 'https://huudis.com',
  accessKey: { accessKeyId: process.env.HUUDIS_ACCESS_KEY_ID!, secretAccessKey: process.env.HUUDIS_SECRET_ACCESS_KEY! },
  workspaceId: 'acc_…', // optional: the workspace to act in
});
const users = await huudis.api.iamUsers();
await huudis.api.iamCreateGroups({ name: 'On call' });

// Your app reading its own users:
const app = new HuudisClient({ issuer: 'https://huudis.com', clientId: 'oc_…', clientSecret: 'cs_…' });
const signedIn = await app.api.appUsers({ status: 'active' });
```

With a `session`, the person's token is used and the key is not. Person-only routes
(password, sessions, account deletion, adding members, …) refuse a key with
`PERSON_ONLY`; see <https://huudis.com/docs/api/authentication>. `signRequest(...)` signs a
request you build yourself.

## What's in the box

| Export | Purpose |
|---|---|
| `verifyAccessToken(tokenOrHeader)` | Module-level — reads `HUUDIS_ISSUER` / `HUUDIS_AUDIENCE` from env. |
| `HuudisClient` | Full surface — OIDC code flow, refresh, userinfo, authz check, `client.api` (every route). |
| `signRequest`, `accessKeyFetch`, `clientCredentialsFetch` | Access-key signing and client credentials for your own requests. |
| `HuudisAuthError` | Thrown on any auth/OIDC/authz failure. |

JWKS keys are fetched once per issuer and cached in-process.

## Docs

- Full docs: <https://huudis.com/docs>
- Playground: <https://huudis.com/dashboard/authz/playground>
- Source: <https://github.com/hachimi-cat/huudis-node>

## License

MIT
