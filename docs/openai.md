# OpenAI: API Workload Identity Federation

A consumer Worker exchanges the issuer token for a short-lived OpenAI API access token. The Worker holds no `sk-` API key.

OpenAI reference: https://developers.openai.com/api/docs/guides/workload-identity-federation

**Status: not tested end to end.** OpenAI documents GitHub Actions, Kubernetes, Google Cloud and other named providers. For a provider it does not list, OpenAI asks you to contact support. The issuer serves standard OIDC discovery and a JWKS with a unique `kid` per key, which is what the settings page asks for. Confirm with OpenAI before you rely on it in production.

## What to put where

| Field | Value |
|---|---|
| OIDC Issuer URL (Organization settings) | `ISSUER` exactly, for example `https://oidc.example.com` |
| Audience (Organization settings) | `https://api.openai.com` |
| Key source | Standard OIDC discovery |
| Service account mapping key | `sub` |
| Service account mapping value | The consumer `sub`, exact, for example `example-openai` |
| `aud` in the consumer `props` | `["https://api.openai.com"]` |
| `sub` in the consumer `props` | The same `sub` as the mapping |

The audience string is a convention of this repo. It must be the same in the OpenAI settings and in `props`.

## 1. Register the provider and mapping

An organization owner opens **Organization Settings > Security > Workload Identity Provider**.

1. Create a provider with the issuer URL and audience above, key source **Standard OIDC discovery**.
2. Add a service account mapping: key `sub`, value `example-openai`, the target project and service account. Optional permissions narrow the token.

Record the identity provider ID and the service account ID. They are identifiers, not secrets.

## 2. Configure the consumer

`examples/openai` is a complete consumer. Put both IDs in `vars` in its `wrangler.jsonc`.

## 3. The exchange

```ts
const { token: jwt } = await env.OIDC.getToken({ aud: "https://api.openai.com" });

const res = await fetch("https://auth.openai.com/oauth/token", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    subject_token: jwt,
    identity_provider_id: env.OPENAI_IDENTITY_PROVIDER_ID,
    service_account_id: env.OPENAI_SERVICE_ACCOUNT_ID,
  }),
});
const { access_token, expires_at } = await res.json();
```

Call the API with `authorization: Bearer <access_token>`. The access token lasts at most 1 hour. OpenAI returns no refresh token: run the exchange again with a new issuer token.

## 4. Deploy and test

```sh
cd examples/openai
npx wrangler deploy
curl https://example-openai.<your-subdomain>.workers.dev/   # lists models
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Exchange returns an authentication error | Check that `iss` equals the issuer URL and `aud` equals the audience, byte for byte. |
| `invalid_grant` | No enabled mapping matches, or more than one matches. Exactly one mapping must match. |
| Exchange succeeds, API call fails | The mapping permissions or the service account's project do not cover the call. |
