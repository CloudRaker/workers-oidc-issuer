# Threat model

## Assets

1. **Signing private keys.** RSA 2048 or larger. Manual mode: one Secrets Store secret per key, `OIDC_KEY_<kid>`. Auto mode: one secret, `OIDC_KEYSET`, with at most 3 keys.
2. **Issued tokens.** RS256 JWTs. Default lifetime 300 seconds. Hard ceiling 3600 seconds.
3. **Consumer identity.** The `sub` and `aud` list in the consumer's service-binding `props`.
4. **Trust configuration at the provider.** AWS IAM provider and role trust policy, GCP pool and provider, Azure federated credential, Vault role. Each pins `ISSUER`, `sub`, and `aud`.
5. **Auto mode only: the Cloudflare API token.** Scope: Account > Secrets Store > Edit.
6. **Auto mode only: the Durable Object storage.** Rows of `kid`, fingerprint, timestamps, status. No private material.
7. **Deploy credentials.** The `wrangler` login or a CI token with Workers Scripts Edit and Secrets Store Edit.

## Trust boundary

The boundary is: anyone who can deploy a Worker in this Cloudflare account.

- A deployer sets `props` on a service binding. Cloudflare guarantees that only a deployer of the calling Worker can set them. The signer reads `ctx.props`. It trusts them as the caller's identity.
- The signer sets `disable_ctx_exports`. Code inside the signer cannot call the `Issuer` entrypoint with runtime props.
- The public fetch handler never signs. It does not import the signer. A static test enforces this.
- A provider trusts `ISSUER`. The signer builds `issuer` and `jwks_uri` from the `ISSUER` variable only. The request never influences them.

Everything inside the Cloudflare account is one trust zone. The issuer does not separate teams inside one account. Use one account per trust zone if you need that.

## What a compromise yields

### A consumer Worker, compromised at runtime

Attacker capability: run code inside the consumer isolate.

Yield in both modes:
- Tokens with the consumer's own `sub`.
- Only for `aud` values on the consumer's allow-list.
- Only up to `TOKEN_TTL_SECONDS`. The consumer can shorten `ttl`. It cannot lengthen it.
- The cloud credentials that this one identity can obtain.

Not yielded: tokens for another `sub`, tokens for another `aud`, the signing key, tokens that outlive the TTL.

Recovery: fix the consumer and redeploy. No key rotation needed. Remove or tighten the provider role if its permissions were too wide.

### The signer Worker, compromised at runtime

Attacker capability: run code inside the signer isolate.

Yield in both modes:
- Read of every private key via the Secrets Store binding. Secrets Store is not an HSM.
- Forged tokens for any `sub` and `aud`, until rotation.

Mitigations:
- Zero runtime dependencies. No supply chain in the bundle.
- `no_nodejs_compat` and `no_nodejs_compat_v2`. CI fails if the bundle contains `node:`.
- Two public routes, `GET` and `HEAD` only. No request body is parsed. No config value is echoed.
- Keys are imported non-extractable. Export through WebCrypto fails. Direct read of the secret is still possible.

Recovery: manual mode: Add, Promote, Remove at once, without the one-hour waits, and accept broken caches for one hour. Auto mode: **Emergency revoke**. Every old key leaves the JWKS within seconds. Providers with a cached JWKS trust the old key for up to their cache lifetime (see 'A provider cache' below). An unknown-`kid` refetch does not help here: a forged token carries the old `kid`, which the cached JWKS still lists.

### An operator laptop

Manual mode yield:
- Keys exist in memory during Add. The CLI never writes them to disk, argv, or logs. A memory dump during that window yields one key.
- The `wrangler` login yields deploy access. A deployer can change `props` on any consumer and mint tokens as any `sub`. This is the trust boundary.

Auto mode yield:
- No key ever exists on the laptop.
- The API token exists in process memory during Setup: in the input buffer, in the validation request header, and on the wrangler child's stdin. JavaScript cannot overwrite a string, so the CLI only drops its references after the upload. Copies can stay in memory until the garbage collector runs or the process exits. Exit the CLI after Setup. Use a token with a short TTL.
- The `wrangler` login yields the same deploy access as above.

Mitigation: protect `wrangler` logins as you protect production deploy keys. Prefer short-lived CI tokens over a long-lived laptop login.

### The auto-mode Cloudflare API token

Attacker capability: write any secret in the account's Secrets Store.

Yield:
- Overwrite `OIDC_KEYSET` with attacker keys. The signer drops every key whose `(kid, fingerprint)` the Durable Object did not generate. Within the 60-second isolate memo, the attacker keys are gone from the JWKS and `getToken` fails closed.
- Denial of service: the signer refuses to sign until the next tick rewrites the keyset.
- Overwrite of other secrets in the account. Scope the token to this account only.

Not yielded: forgery. Forgery needs the token and write access to the Durable Object storage. These are two independent permissions.

Recovery: revoke the token in the Cloudflare dashboard and create a new one with the same scope (Account > Secrets Store > Edit, this account only). Two supported paths. (1) Run **Setup** again, choose auto and the same ISSUER. Setup validates the new token against api.cloudflare.com, updates `OIDC_CF_API_TOKEN` in place and keeps the existing `OIDC_KEYSET`. Note: Setup rewrites `wrangler.jsonc` and redeploys, but it keeps the existing `ROTATION_INTERVAL_HOURS`, `ROTATION_GRACE_HOURS`, `ROTATE_NONCE`, `REVOKE_BEFORE` and `RETIRE_KIDS` values. A custom schedule survives and no rotation or revoke starts. To change the schedule or clear a marker, use **Edit schedule** or edit the var and deploy. (2) Update the secret by hand, with no redeploy. In `packages/worker`, with `<STORE_ID>` taken from `vars.SECRETS_STORE_ID` in `wrangler.jsonc`:

```sh
npx wrangler secrets-store secret list <STORE_ID> --remote --per-page 100   # copy the ID of OIDC_CF_API_TOKEN
npx wrangler secrets-store secret update <STORE_ID> --secret-id <ID> --remote
```

Answer `y` to "Do you want to update the secret value?", then paste the new token at the masked prompt. Never pass `--value`; it lands in shell history. No redeploy is needed. The binding serves the new value after about 5 s. The KeyRing reads the token only on a tick that writes the keyset (scheduled rotation, Rotate now, Emergency revoke, Retire key or a provenance rewrite). A tick with nothing to change never reads it, so a JWKS fetch does not confirm the new token. To confirm it now, run Rotate now and check that a `next` key appears in the JWKS. If a `next` key is already published, Rotate now has no effect; use path (1) instead, Setup validates the token against api.cloudflare.com before it stores it.

### The auto-mode Durable Object storage

Attacker capability: read and write rows via Data Studio or an account API.

Yield:
- Read: `kid`, fingerprint, timestamps, status. No private material. A test queries the SQLite storage and asserts no `"d":` member.
- Write: insert a provenance row for an attacker key. The signer will trust that key when it appears in `OIDC_KEYSET`. Without the API token, the attacker cannot put it there.

Not yielded alone: forgery. See above.

Recovery: run **Emergency revoke**. The same tick retires every key created before `REVOKE_BEFORE`, generates a fresh active key, and marks every row whose `(kid, fingerprint)` has no matching material in `OIDC_KEYSET` as `deleted`. A row the attacker inserted never gets material without the API token, so it drops on the next tick even without a revoke.

If the JWKS does not change within one minute after Emergency revoke, the attacker edited the `meta` table. Every tick stops at "keyset behind the DO; waiting for propagation" only when both hold: `keyset_version` is above the version in `OIDC_KEYSET` and `last_write` is less than 60 s ago or in the future. Either value alone does not stall: a high `keyset_version` only delays the next rewrite by 60 s, and a future `last_write` with matching versions is ignored. Check both rows in Data Studio before you reset. If only `keyset_version` is high, wait one tick; no reset is needed. Reset the storage only when the warning repeats for more than one minute: in the Cloudflare dashboard open the `KeyRing` Durable Object, object `default`, in Data Studio and run:

```sql
DELETE FROM keys;
DELETE FROM meta;
INSERT INTO meta(k, v) VALUES ('keyset_version', '1000000000');
```

Keep the `keyset_version` row high. With no `keyset_version` row the version restarts at 0, the propagation-lag guard is off, and every tick in the next few seconds marks the key it just wrote as lost and generates another one. Then fetch `${ISSUER}/.well-known/jwks.json` to trigger a tick, or run Emergency revoke again. Do not use a `deleted_classes` migration: it also drops `keyset_version` and needs a second migration to re-add the class.

### The Cloudflare account

Attacker capability: full account access.

Yield in both modes: everything. Read keys, change `props`, mint any token, change `ISSUER`, redeploy.

This is outside the model. The issuer does not defend against the platform it runs on. Mitigations are account level: SSO, hardware keys, least-privilege API tokens, audit logs.

### A provider cache

Providers cache the JWKS for up to one hour. A removed key is still trusted until the cache expires.

Manual mode mitigation: the fixed one-hour waits in Add → Promote → Remove.
Auto mode mitigation: the grace period keeps a retiring key in the JWKS for `ROTATION_GRACE_HOURS` after promotion. **Emergency revoke** skips grace. Providers that see an unknown `kid` refetch the JWKS at once. Neither path revokes a key inside a provider cache; provider-side trust must be rotated when a key leaked.

## Key handling rules

- `kid` matches `^[a-z0-9]{1,32}$`.
- A private JWK must have exactly these members: `alg d dp dq e kid kty n p q qi use`. Any extra member rejects the key. Manual mode also requires the JWK `kid` to equal the binding `kid`.
- Import uses `RSASSA-PKCS1-v1_5` with `SHA-256`, non-extractable, `sign` only. Modulus length must be 2048 or more.
- The public JWK is built by allow-list: `kty n e kid alg use`. Never by spread or delete. Never by `exportKey`.
- A broken non-active key is omitted from the JWKS. A broken active key makes `getToken` throw. The JWKS still serves the others.
- Logs carry the `kid` only. Tests spy on `console` and assert that no `"d":`, `"p":`, `"q":`, secret value, or token appears.

## Token rules

- Header: `alg RS256`, `typ JWT`, `kid`.
- Claims: `iss`, `sub`, `aud` (string), `iat`, `nbf = iat`, `exp = iat + ttl`, `jti = crypto.randomUUID()`.
- `aud` must be an exact member of the consumer's `props.aud`.
- Default TTL 300 seconds. Range 60 to `TOKEN_TTL_SECONDS`. `TOKEN_TTL_SECONDS` range 60 to 3600.
- The token appears only in a POST body in every example and document.

## Non-goals

- Protection against a compromised Cloudflare account or a malicious Cloudflare employee.
- Hardware key storage. Secrets Store is software storage.
- Separation of trust between Workers inside one Cloudflare account.
- User authentication. This is workload identity only. There is no login, no `nonce`, no `at_hash`.
- Token revocation lists. Tokens are short-lived instead.
- Algorithms other than RS256.
