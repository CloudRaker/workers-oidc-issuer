# AWS: AssumeRoleWithWebIdentity

A consumer Worker exchanges the issuer token for AWS credentials with `sts:AssumeRoleWithWebIdentity`. The credentials live for 900 seconds in the example.

## What to put where

| Field | Value |
|---|---|
| IAM identity provider URL | `ISSUER` exactly, for example `https://oidc.example.com`. No trailing slash. |
| IAM identity provider audience (client ID) | `sts.amazonaws.com` |
| `aud` in the consumer `props` | `["sts.amazonaws.com"]` |
| `sub` in the consumer `props` | The consumer identity, for example `example-consumer` |
| Trust policy condition `<host>:sub` | The same `sub`, exact string match |
| Trust policy condition `<host>:aud` | `sts.amazonaws.com` |

`<host>` is `ISSUER` without `https://`. For `https://oidc.example.com` it is `oidc.example.com`.

## 1. Create the identity provider

```sh
aws iam create-open-id-connect-provider \
  --url https://oidc.example.com \
  --client-id-list sts.amazonaws.com
```

AWS reads `https://oidc.example.com/.well-known/openid-configuration` and the JWKS. AWS trusts the TLS root of the issuer. You do not need a thumbprint for a Cloudflare-hosted issuer.

The provider ARN is `arn:aws:iam::<ACCOUNT_ID>:oidc-provider/oidc.example.com`.

## 2. Create the role

Trust policy (`trust.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.example.com:aud": "sts.amazonaws.com",
          "oidc.example.com:sub": "example-consumer"
        }
      }
    }
  ]
}
```

```sh
aws iam create-role \
  --role-name example-consumer \
  --assume-role-policy-document file://trust.json \
  --max-session-duration 3600

aws iam attach-role-policy \
  --role-name example-consumer \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

Use one role per `sub`. Use `StringEquals` on `sub`. Do not use `StringLike` with a wildcard.

## 3. Exchange the token

The consumer sends one POST. The token travels in the body only.

```ts
const { token } = await env.OIDC.getToken({ aud: "sts.amazonaws.com" });

const res = await fetch("https://sts.us-east-1.amazonaws.com/", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  },
  body: new URLSearchParams({
    Action: "AssumeRoleWithWebIdentity",
    Version: "2011-06-15",
    RoleArn: "arn:aws:iam::123456789012:role/example-consumer",
    RoleSessionName: "example-consumer",
    WebIdentityToken: token,
    DurationSeconds: "900",
  }),
});
const json = await res.json();
const creds = json.AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials;
// creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken, creds.Expiration
```

`examples/consumer/src/index.ts` has the full code with a credential cache.

## Limits

- `RoleSessionName`: 2 to 64 characters, `[\w+=,.@-]`.
- `DurationSeconds`: 900 to the role's maximum session duration.
- `WebIdentityToken`: 4 to 20000 characters. An RS256 token from this issuer is about 700 characters.
- The token `exp` must be in the future when STS receives it. Default TTL is 300 seconds. Do not cache tokens.

## Consumer `wrangler.jsonc`

```jsonc
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": { "sub": "example-consumer", "aud": ["sts.amazonaws.com"] }
  }
]
```

## Troubleshooting

- `InvalidIdentityToken: No OpenIDConnect provider found in your account for https://...`: the provider URL does not match `iss`. Run `node packages/cli/dist/bin.js verify --issuer <url>` from the repo root and compare.
- `InvalidIdentityToken: Couldn't retrieve verification key from your identity provider`: AWS cannot fetch the JWKS, or the `kid` is not in it. Wait up to one hour after a manual Promote.
- `AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity`: the `sub` or `aud` condition does not match. Compare the trust policy with the consumer `props`.
- `ExpiredTokenException`: the token lived longer than its TTL before the call. Call `getToken` right before the STS call.
