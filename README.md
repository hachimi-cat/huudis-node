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

## What's in the box

| Export | Purpose |
|---|---|
| `verifyAccessToken(tokenOrHeader)` | Module-level — reads `HUUDIS_ISSUER` / `HUUDIS_AUDIENCE` from env. |
| `HuudisClient` | Full surface — OIDC code flow, refresh, userinfo, authz check. |
| `HuudisAuthError` | Thrown on any auth/OIDC/authz failure. |

JWKS keys are fetched once per issuer and cached in-process.

## Docs

- Full docs: <https://huudis.com/docs>
- Playground: <https://huudis.com/dashboard/authz/playground>
- Source: <https://github.com/hachimi-cat/huudis-node>

## License

MIT
