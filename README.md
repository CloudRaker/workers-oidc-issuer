# workers-oidc-issuer

A self-hosted OIDC workload-identity issuer for Cloudflare Workers.

A Worker calls the issuer and gets a short-lived RS256 JWT. The JWT asserts the Worker's identity. AWS, GCP, Azure, Vault, the Claude API and the OpenAI API exchange the JWT for short-lived credentials. You store no cloud or AI provider keys anywhere.

New to workload identity federation? Read the visual explainer at [oidcfederation.cloudraker.com](https://oidcfederation.cloudraker.com).

## Why

Workers have no native identity token. Teams store long-lived cloud keys as Worker secrets. One platform breach forces a rotation of every key.

With this issuer, a Worker holds no cloud key. A leaked token is valid for 300 seconds by default, for one identity, for one audience.

## Trust model

Read [docs/threat-model.md](docs/threat-model.md) for the full model. The short version:

- The trust boundary is "anyone who can deploy a Worker in this Cloudflare account".
- A consumer Worker declares its identity at deploy time, in `wrangler.jsonc`, as `props` on the service binding. Cloudflare guarantees that only a deployer of the calling Worker can set these props.
- The signer sets `disable_ctx_exports`. The signer cannot call itself with runtime props.
- A consumer compromised at runtime mints tokens only as its own `sub`, only for its allow-listed `aud`, only up to `TOKEN_TTL_SECONDS`.
- The signer Worker can read its private keys. Secrets Store is not an HSM. Mitigation: zero runtime dependencies, `no_nodejs_compat`, two public routes, a tiny code surface.

### Two key-management modes

You choose the mode with `vars.ROTATION`. You do not need a Cloudflare API token unless you choose auto mode.

| | manual (default) | auto (opt-in) |
|---|---|---|
| Who generates keys | You, on your machine, in memory | A Durable Object, inside Cloudflare |
| Where keys travel | stdin to `wrangler`, then Secrets Store | Never leave Cloudflare |
| Rotation | You run Add, Promote, Remove in the CLI | A cron rotates on a schedule |
| Cloudflare API token | None | Required: Account > Secrets Store > Edit |
| Long-lived credential in the system | None | The API token |

**Switching auto → manual.** Setup deletes the stored token copy (`OIDC_CF_API_TOKEN`) and the keyset after the manual deploy. The token itself stays valid: revoke it at https://dash.cloudflare.com/profile/api-tokens.

**Auto-mode trade-off.** The API token is a long-lived credential with account-wide Secrets Store write. The Durable Object keeps a provenance pin: the fingerprint of every key it generated. The signer drops any key that the pin does not confirm. A leaked token alone can cause denial of service. It cannot cause forgery. Forgery needs the token and write access to the Durable Object's storage. Those are two independent permissions.

Verified 2026-10-22: a Secrets Store value update reaches a running Worker in about 5 seconds, without a redeploy. Auto mode depends on this.

## Quickstart (5 minutes)

Requirements: Node 22.18 or newer (see `.nvmrc` and `engines`), pnpm, a Cloudflare account with Workers enabled.

```sh
git clone https://github.com/<you>/workers-oidc-issuer
cd workers-oidc-issuer
pnpm install
pnpm --filter @workers-oidc-issuer/worker exec wrangler login
pnpm --filter workers-oidc-issuer build
node packages/cli/dist/bin.js
```

`wrangler` is a dev dependency of `packages/worker`. It is not on your PATH. Skip the login line when you are already logged in.

The CLI opens the **Home** screen. Choose **Setup**. The wizard does these steps:

1. Checks your `wrangler` login (see the login line above).
2. Pins the account in `wrangler.jsonc` when your login reaches more than one account.
3. Finds or creates the Secrets Store.
4. Asks for the mode. Manual is the default. Auto asks for an API token.
5. Asks for `ISSUER`. Use a custom domain in production. A custom domain needs a route before Setup. Add this to `packages/worker/wrangler.jsonc` first: `"routes": [{ "pattern": "oidc.example.com", "custom_domain": true }]`. The zone must be in the same Cloudflare account. `wrangler deploy` creates the DNS record and certificate. Without the route, Verify, Keys (auto mode) and `keys list --json` cannot reach `ISSUER`.
6. Manual: generates the first key in memory and uploads it over stdin. Auto: stores the API token and an empty keyset.
7. Writes `packages/worker/wrangler.jsonc`.
8. Runs `wrangler deploy`.
9. Opens **Verify**.

Then choose **Consumer snippet**. Enter your consumer Worker name, `sub`, and `aud` list. Paste the printed `services` block into the consumer's `wrangler.jsonc`.

Non-interactive commands:

```sh
node packages/cli/dist/bin.js keys list --json
node packages/cli/dist/bin.js verify --issuer https://oidc.example.com
node packages/cli/dist/bin.js keygen --kid k202610220a1b
```

Run these from the repo root, or pass `--worker-dir packages/worker`. The package is private and not published, so the `workers-oidc-issuer` bin name is not on your PATH.

## Consumer usage

`examples/consumer` is a complete example that exchanges the token with AWS STS.

```jsonc
// consumer wrangler.jsonc
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": { "sub": "example-consumer", "aud": ["sts.amazonaws.com"] }
  }
]
```

```ts
const { token, expiresAt, kid } = await env.OIDC.getToken({ aud: "sts.amazonaws.com" });
```

Send the token only in a POST body. Never put it in a URL or a log.

The token claims are `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`. `aud` is a string. `ttl` can shorten the lifetime. It cannot lengthen it past `TOKEN_TTL_SECONDS`.

Provider guides:

- [docs/aws.md](docs/aws.md)
- [docs/gcp.md](docs/gcp.md)
- [docs/azure.md](docs/azure.md)
- [docs/vault.md](docs/vault.md)
- [docs/anthropic.md](docs/anthropic.md): Claude API, with `examples/anthropic`
- [docs/openai.md](docs/openai.md): OpenAI API, with `examples/openai` (not tested end to end)

## Public endpoints

The signer serves two routes, `GET` and `HEAD` only:

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`

Both carry `Cache-Control: public, max-age=3600` on a 200 response. Providers cache the JWKS for up to one hour. This drives the one-hour waits below.

## Manual rotation procedure

Open **Keys** in the CLI. The screen shows every binding kid, marked ACTIVE or PUBLISHED.

1. **Add.** The CLI generates a key in memory, creates the secret over stdin, adds the binding, and deploys. The new key is now published in the JWKS. It does not sign yet.
2. **Wait at least 1 hour.** Provider JWKS caches must pick up the new key.
3. **Promote.** The CLI sets `ACTIVE_KID` to the new kid and deploys. New tokens now carry the new kid.
4. **Wait at least 1 hour.** Tokens signed with the old key must expire. Provider caches must refresh.
5. **Remove.** The CLI refuses to remove the ACTIVE kid. It removes the binding, deploys, finds the secret id with `secret list`, and deletes the secret. The CLI lists up to 100 secrets, the account limit. If the lookup still misses, delete the secret by hand: `pnpm --filter @workers-oidc-issuer/worker exec wrangler secrets-store secret list <STORE_ID> --remote --per-page 100`, then `pnpm --filter @workers-oidc-issuer/worker exec wrangler secrets-store secret delete <STORE_ID> --secret-id <id> --remote`. A private key that stays in the store counts against the 100-secret limit.

Full sequence: Add → wait 1 h → Promote → wait 1 h → Remove.

Every step is a `wrangler.jsonc` change plus a deploy. You can review the change in a pull request. No Cloudflare API token is involved.

## Auto-mode schedule

Variables: `ROTATION_INTERVAL_HOURS` (default 720, range 24..8760) and `ROTATION_GRACE_HOURS` (default 24, range 2..168, less than half the interval). A cron runs at minute 17 of every hour. The fetch handler also triggers a tick when the last tick is older than 1 hour or when a policy variable changed.

The JWKS over time, with interval I and grace G:

| Time | JWKS contents | Signing key |
|---|---|---|
| t = 0 | `[active]` | active |
| t = I - G | `[active, next]` | active |
| t = I | `[new active, retiring]` | new active |
| t = I + G | `[active]` | active |

The keyset holds at most 3 keys. A kid encodes its creation time, so the **Keys** screen shows the age of each key.

Actions on the **Keys** screen in auto mode:

- **Rotate now.** Sets `ROTATE_NONCE` to a random value and deploys. A `next` key appears at once, unless one is already published. In that case Rotate now has no effect and the pending promotion continues on schedule.
- **Emergency revoke.** Double confirm. Sets `REVOKE_BEFORE` to the current time and deploys. Every key created before that time is removed on the same tick. A fresh active key is generated. The signer drops every old key within seconds. New tokens use the fresh key at once. A provider that cached the JWKS still trusts the old key until its cache expires: typically up to 1 h, longer for providers that ignore `max-age`. Tokens signed with the old key, including tokens minted by an attacker who holds it, verify until then or until their `exp`, whichever comes first. If you suspect the key leaked, also rotate the provider-side trust (role, audience, or the trust relationship) or remove the issuer from the provider until the cache window has passed.
- **Retire key.** Pick a non-active kid. The Durable Object ignores an active kid and warns.
- **Edit schedule.** Change interval and grace with validation, then deploy.

## Security notes and FAQ

**Which permissions does a deploy token need?** Workers Scripts Edit and Secrets Store Edit. Without Secrets Store Edit, `wrangler deploy` fails with "failed to fetch secrets store binding due to authorization error".

**Which permissions does the auto-mode API token need?** Account > Secrets Store > Edit, scoped to this account only. Set a TTL if your policy allows it.

**Why a custom domain for `ISSUER`?** Providers pin `ISSUER` in their trust config. A `workers.dev` hostname is tied to the account subdomain. A move to another account changes the hostname and breaks every trust relationship. The signer builds `issuer` and `jwks_uri` from `ISSUER` only, never from the request. Route the custom domain to the Worker before Setup: add `"routes": [{ "pattern": "oidc.example.com", "custom_domain": true }]` to `packages/worker/wrangler.jsonc`, with the zone in the same account.

**How many keys can I have?** Secrets Store allows 100 secrets per account. Manual mode publishes 1 to 10 keys. Auto mode holds at most 3 keys in one secret.

**Which environment variables does CI need?** `CLOUDFLARE_API_TOKEN` for the deploy. The CLI never passes `CLOUDFLARE_ACCOUNT_ID`. It pins `account_id` in `wrangler.jsonc` instead.

**Why does the Durable Object never store private keys?** Cloudflare Data Studio can read and write Durable Object storage. The Durable Object stores only kid, fingerprint, and timestamps. Private JWKs exist only in memory between generation and the Secrets Store write. A test queries the SQLite storage and asserts that no `"d":` member is present.

**Can the public fetch handler mint a token?** No. The default export does not import the signer. `disable_ctx_exports` blocks runtime access to the `Issuer` entrypoint from inside the Worker. A static test enforces both.

**What does a consumer control?** Only `aud` from its own allow-list, and a `ttl` that can shrink. `sub` comes from `props`, fixed at deploy time.

**Which signing algorithm?** RS256 only. RSA modulus 2048 bits or more. Every key is imported non-extractable.

## Repository layout

- `packages/worker` — the signer. Zero runtime dependencies.
- `packages/cli` — the `workers-oidc-issuer` TUI and `--json` commands.
- `examples/consumer` — a consumer that exchanges the token with AWS STS.
- `examples/anthropic` — a consumer that calls the Claude API with a federated token.
- `examples/openai` — a consumer that calls the OpenAI API with a federated token.
- `docs/` — provider guides and the threat model.

## Development

```sh
pnpm install
pnpm typecheck
pnpm lint     # fails if the signer bundle imports node:
pnpm test
pnpm build
```

## License

MIT.
