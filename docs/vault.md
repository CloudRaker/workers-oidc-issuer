# HashiCorp Vault: JWT auth method

A consumer Worker logs in to Vault with the issuer token. Vault returns a client token with the policies of the role.

## What to put where

| Field | Value |
|---|---|
| `oidc_discovery_url` | `ISSUER` exactly, for example `https://oidc.example.com` |
| `bound_issuer` | The same `ISSUER` string |
| Role `bound_subject` | The consumer `sub`, exact match |
| Role `bound_audiences` | A value of your choice, for example `vault` |
| `aud` in the consumer `props` | The same value, for example `["vault"]` |
| `sub` in the consumer `props` | The same `bound_subject` string |
| Role `user_claim` | `sub` |

Use one Vault role per `sub`.

## 1. Enable and configure the auth method

```sh
vault auth enable jwt

vault write auth/jwt/config \
  oidc_discovery_url="https://oidc.example.com" \
  bound_issuer="https://oidc.example.com"
```

Vault fetches `https://oidc.example.com/.well-known/openid-configuration` and the JWKS. Vault refreshes the JWKS when it sees an unknown `kid`.

## 2. Create a policy and a role

```sh
vault policy write example-consumer - <<'EOF'
path "secret/data/example-consumer/*" {
  capabilities = ["read"]
}
EOF

vault write auth/jwt/role/example-consumer \
  role_type="jwt" \
  user_claim="sub" \
  bound_subject="example-consumer" \
  bound_audiences="vault" \
  token_policies="example-consumer" \
  token_ttl="5m" \
  token_max_ttl="15m"
```

`bound_subject` is an exact match. `bound_audiences` accepts a list. Keep it to one value per role.

## 3. Log in

One POST. The issuer token travels in the JSON body.

```ts
const { token } = await env.OIDC.getToken({ aud: "vault" });

const res = await fetch("https://vault.example.com/v1/auth/jwt/login", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ role: "example-consumer", jwt: token }),
});
const { auth } = await res.json();
// auth.client_token, auth.lease_duration
```

Use `auth.client_token` in the `X-Vault-Token` header for later calls. Renew or re-login before `lease_duration` ends.

## Consumer `wrangler.jsonc`

```jsonc
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": { "sub": "example-consumer", "aud": ["vault"] }
  }
]
```

## Notes

- Vault checks `nbf`, `iat`, and `exp`. The issuer sets all three. Vault allows a small clock skew by default.
- Vault accepts RS256 by default. You do not need to set `jwt_supported_algs`.
- If you run Vault with a private CA, set `oidc_discovery_ca_pem` only when the issuer uses that CA. A Cloudflare-hosted issuer uses a public CA.

## Troubleshooting

- `error validating token: invalid audience`: `bound_audiences` and the `aud` in `props` differ.
- `error validating token: invalid issuer`: `bound_issuer` and the token `iss` differ. Check for a trailing slash.
- `error validating token: invalid subject (sub) claim`: `bound_subject` and `sub` differ. Both are exact-match strings.
- `error validating token: error verifying token signature`: Vault cannot fetch the JWKS, or the `kid` is not in it yet. Vault refreshes the JWKS on an unknown `kid`, so retry once; if it persists, check that the issuer URL in `oidc_discovery_url` serves `/.well-known/jwks.json` from Vault's network.
- `error validating token: invalid algorithm (alg) header parameter`: `jwt_supported_algs` excludes RS256.
