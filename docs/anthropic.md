# Anthropic: Claude API Workload Identity Federation

A consumer Worker exchanges the issuer token for a short-lived Claude API access token. The Worker holds no `sk-ant-` API key.

Anthropic reference: https://platform.claude.com/docs/en/manage-claude/workload-identity-federation

## Compatibility

The issuer token meets every Anthropic JWT rule without changes:

| Anthropic rule | Issuer token |
|---|---|
| Asymmetric algorithm | RS256 |
| `kid` in the header, present in the JWKS | Yes |
| `sub`, `iat`, `exp` present | Yes |
| Lifetime at most 1 hour | 300 s default, 3600 s ceiling |
| `jti` used once only | A new `jti` on every `getToken` call |
| Discovery on public HTTPS, port 443 | `ISSUER/.well-known/openid-configuration` on your custom domain |

**Get a new issuer token for every exchange.** Anthropic rejects a second exchange with the same `jti` (reason `jti_reused`). Never cache the issuer token. Cache the Anthropic access token instead.

**The access token lives at most twice the remaining issuer token lifetime.** With the 300 s default, expect an access token of about 600 s. Anthropic computes the lifetime as the lesser of the rule's `token_lifetime_seconds` and twice the remaining JWT lifetime.

## What to put where

| Field | Value |
|---|---|
| Issuer URL (Console) | `ISSUER` exactly, for example `https://oidc.example.com`. No trailing slash. |
| JWKS source (Console) | Discovery (default) |
| Rule match: subject | The consumer `sub`, exact, for example `example-anthropic`. No trailing `*`. |
| Rule match: audience | `https://api.anthropic.com` |
| Rule scope | `workspace:inference` if the Worker only calls Messages. `workspace:developer` for Files, Skills or Managed Agents. |
| `aud` in the consumer `props` | `["https://api.anthropic.com"]` |
| `sub` in the consumer `props` | The same `sub` as the rule |

The audience string is a convention of this repo. Anthropic does not require a specific value. It must be the same in the rule and in `props`.

## 1. Register the issuer, service account and rule

In the Claude Console, open **Settings > Workload identity** and select **Connect workload**. Choose **Custom OIDC**.

1. Issuer URL: your `ISSUER`.
2. Match: subject `example-anthropic`, audience `https://api.anthropic.com`.
3. Scope: `workspace:inference`.
4. Select **Verify issuer**. Anthropic fetches the discovery document and the JWKS. A failure here means the custom domain does not reach the issuer Worker.

Record these values: organization ID (UUID), rule ID (`fdrl_...`), service account ID (`svac_...`), workspace ID (`wrkspc_...`). They are identifiers, not secrets.

## 2. Configure the consumer

`examples/anthropic` is a complete consumer. Put the four IDs in `vars` in its `wrangler.jsonc`:

```jsonc
"vars": {
  "ANTHROPIC_ORGANIZATION_ID": "<uuid>",
  "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_...",
  "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_...",
  "ANTHROPIC_WORKSPACE_ID": "wrkspc_..."
},
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": { "sub": "example-anthropic", "aud": ["https://api.anthropic.com"] }
  }
]
```

## 3. The exchange

```ts
const { token: jwt } = await env.OIDC.getToken({ aud: "https://api.anthropic.com" });

const res = await fetch("https://api.anthropic.com/v1/oauth/token", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: jwt,
    federation_rule_id: env.ANTHROPIC_FEDERATION_RULE_ID,
    organization_id: env.ANTHROPIC_ORGANIZATION_ID,
    service_account_id: env.ANTHROPIC_SERVICE_ACCOUNT_ID,
    workspace_id: env.ANTHROPIC_WORKSPACE_ID,
  }),
});
const { access_token, expires_in } = await res.json();
```

Call the API with `authorization: Bearer <access_token>` and `anthropic-version: 2023-06-01`. Do not send `x-api-key`.

## 4. Deploy and test

```sh
cd examples/anthropic
npx wrangler deploy
curl https://example-anthropic.<your-subdomain>.workers.dev/
```

## Troubleshooting

Every denied exchange returns the same `401 Authentication failed`. Open **Settings > Workload identity > Authentication history** in the Console for the real reason.

| Reason or symptom | Fix |
|---|---|
| `jti_reused` | The Worker sent the same issuer token twice. Call `getToken` for every exchange, also on retry. |
| `match_subject_prefix` | The rule subject does not equal `props.sub`. The match is case-sensitive. |
| Audience mismatch | The rule audience does not equal the `aud` you passed to `getToken`. |
| Signature error right after a key rotation | Anthropic caches the JWKS for up to 1 minute. Publish a new key at least 15 minutes before it signs. Manual mode (Add, wait 1 h, Promote) and auto mode (grace period) already do this. |
| `403` on an API call after a successful exchange | The rule scope does not cover the endpoint. |
