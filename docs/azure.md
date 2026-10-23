# Azure: Workload identity federation

A consumer Worker exchanges the issuer token at Microsoft Entra ID for an access token. The target is an app registration or a user-assigned managed identity with a federated identity credential.

## What to put where

| Field | Value |
|---|---|
| Federated credential `issuer` | `ISSUER` exactly, for example `https://oidc.example.com` |
| Federated credential `subject` | The consumer `sub`, exact match, for example `example-consumer` |
| Federated credential `audiences` | `["api://AzureADTokenExchange"]` |
| `aud` in the consumer `props` | `["api://AzureADTokenExchange"]` |
| `sub` in the consumer `props` | The same `subject` string |

## Rules that Entra ID enforces

- `subject` must match `sub` exactly. Entra ID compares the strings. Case matters.
- `issuer` must match `iss` exactly. Entra ID fetches `{issuer}/.well-known/openid-configuration`.
- The audience must be exactly `api://AzureADTokenExchange`.
- The token must be RS256. This issuer signs RS256 only.
- Each app registration or managed identity holds at most 20 federated identity credentials.
- `issuer` is limited to 600 characters. `subject` is limited to 600 characters.
- The `issuer` and `subject` pair must be unique inside one app or identity.

## 1. Create the federated credential

App registration:

```sh
az ad app federated-credential create \
  --id <APP_OBJECT_ID> \
  --parameters '{
    "name": "cf-example-consumer",
    "issuer": "https://oidc.example.com",
    "subject": "example-consumer",
    "audiences": ["api://AzureADTokenExchange"],
    "description": "Cloudflare Worker example-consumer"
  }'
```

User-assigned managed identity:

```sh
az identity federated-credential create \
  --name cf-example-consumer \
  --identity-name example-consumer \
  --resource-group my-rg \
  --issuer https://oidc.example.com \
  --subject example-consumer \
  --audiences api://AzureADTokenExchange
```

Then assign Azure roles to the app's service principal or to the managed identity.

## 2. Exchange the token

One POST. The issuer token is the `client_assertion` in the body.

```ts
const { token } = await env.OIDC.getToken({ aud: "api://AzureADTokenExchange" });

const res = await fetch("https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    client_id: "<CLIENT_ID>",
    scope: "https://management.azure.com/.default",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: token,
    grant_type: "client_credentials",
  }),
});
const { access_token, expires_in } = await res.json();
```

For a managed identity, `client_id` is the identity's client ID. For storage use `https://storage.azure.com/.default`. For Key Vault use `https://vault.azure.net/.default`.

## Consumer `wrangler.jsonc`

```jsonc
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": { "sub": "example-consumer", "aud": ["api://AzureADTokenExchange"] }
  }
]
```

## Troubleshooting

- `AADSTS70021: No matching federated identity record found for presented assertion`: `issuer`, `subject`, or `audiences` differ from the token claims. Decode the token header and payload locally and compare each field. Do not paste the token into a web site. Right after `az ad app federated-credential create` this error can also mean the credential has not replicated yet; wait a few minutes and retry.
- `AADSTS700211: No matching federated identity record found for presented assertion issuer '<iss>'`: the credential `issuer` does not equal the token `iss`. Common cause: `ISSUER` changed, or one side has a trailing slash.
- `AADSTS700213: No matching federated identity record found for presented assertion subject '<sub>'`: `subject`, `issuer`, or `audiences` differ from the token claims. Matching is case-sensitive. Compare each value character by character.
- `AADSTS900612: Failed to parse provider signing keys`: Entra ID fetched the JWKS but could not use it. Check `/.well-known/jwks.json` serves RS256 keys and the token `kid` is present. After a manual Promote, wait up to one hour for the Entra cache.
- `AADSTS700024: Client assertion is not within its valid time range`: the token `exp` has passed, or `nbf`/`iat` is in the future from Entra ID's clock. Request a fresh token with `getToken` right before the exchange and do not cache it past `exp`. If you see this on freshly minted tokens, lower `TOKEN_TTL_SECONDS` or pass a shorter `ttl` to `getToken` so `exp` stays well inside the exchange window.
