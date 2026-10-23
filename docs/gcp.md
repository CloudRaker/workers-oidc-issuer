# GCP: Workload Identity Federation

A consumer Worker exchanges the issuer token at the GCP Security Token Service. It gets a federated access token. It can then impersonate a service account.

## What to put where

| Field | Value |
|---|---|
| Provider `--issuer-uri` | `ISSUER` exactly, for example `https://oidc.example.com` |
| Provider `--allowed-audiences` | `https://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>` |
| `aud` in the consumer `props` | The same allowed audience string |
| `sub` in the consumer `props` | The consumer identity, for example `example-consumer` |
| Attribute mapping | `google.subject=assertion.sub` |
| IAM member | `principal://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/subject/example-consumer` |

`PROJECT_NUMBER` is the numeric project number, not the project ID.

## 1. Create the pool and the provider

```sh
export PROJECT_ID=my-project

gcloud services enable \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  --project="$PROJECT_ID"

export PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
export POOL=cf-workers
export PROVIDER=oidc-issuer
export AUD="https://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER"

gcloud iam workload-identity-pools create "$POOL" \
  --project="$PROJECT_ID" \
  --location=global \
  --display-name="Cloudflare Workers"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
  --project="$PROJECT_ID" \
  --location=global \
  --workload-identity-pool="$POOL" \
  --issuer-uri="https://oidc.example.com" \
  --allowed-audiences="$AUD" \
  --attribute-mapping="google.subject=assertion.sub" \
  --attribute-condition="assertion.sub == 'example-consumer'"
```

New projects have these APIs disabled. Steps 1 to 3 fail with `SERVICE_DISABLED` without them.

The attribute condition is optional. It blocks every `sub` that you did not list.

`google.subject` is limited to 127 bytes. Keep `sub` short.

## 2. Grant access

Create a service account and let the federated identity impersonate it.

```sh
gcloud iam service-accounts create example-consumer --project="$PROJECT_ID"

gcloud iam service-accounts add-iam-policy-binding \
  "example-consumer@$PROJECT_ID.iam.gserviceaccount.com" \
  --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/subject/example-consumer"
```

Then grant the service account the roles your Worker needs.

## 3. Exchange the token

Two POST calls. The issuer token travels in the first body. The federated token travels in the second `Authorization` header.

```ts
const AUD = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/cf-workers/providers/oidc-issuer";
const { token } = await env.OIDC.getToken({ aud: AUD });

// 1. Federated access token
const sts = await fetch("https://sts.googleapis.com/v1/token", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
    audience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/cf-workers/providers/oidc-issuer",
    scope: "https://www.googleapis.com/auth/cloud-platform",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    subjectToken: token,
  }),
});
const { access_token: federated } = await sts.json();

// 2. Service account access token
const sa = await fetch(
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/example-consumer@my-project.iam.gserviceaccount.com:generateAccessToken",
  {
    method: "POST",
    headers: { authorization: `Bearer ${federated}`, "content-type": "application/json" },
    body: JSON.stringify({ scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "900s" }),
  },
);
const { accessToken, expireTime } = await sa.json();
```

Note the two audience forms. The JWT `aud` and `--allowed-audiences` start with `https://`. The STS `audience` field starts with `//`.

## Consumer `wrangler.jsonc`

```jsonc
"services": [
  {
    "binding": "OIDC",
    "service": "oidc-issuer",
    "entrypoint": "Issuer",
    "props": {
      "sub": "example-consumer",
      "aud": ["https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/cf-workers/providers/oidc-issuer"]
    }
  }
]
```

## Limits

- `google.subject`: 127 bytes.
- The provider accepts RS256 and ES256. This issuer signs RS256.
- GCP fetches `ISSUER/.well-known/openid-configuration` on each verification, with caching. Wait up to one hour after a manual Promote.
- `aud` in the consumer `props` is limited to 512 characters by the issuer. The default GCP audience fits.

## Troubleshooting

- `invalid_grant: The audience in JWT does not match`: the `aud` in `props` and `--allowed-audiences` differ. Copy the value from the one to the other.
- `invalid_grant: Unable to verify the OIDC token signature`: GCP cannot fetch the JWKS, or the `kid` is not in it yet.
- `SERVICE_DISABLED` or `API [...] not enabled`: run the `gcloud services enable` command in step 1.
- `PERMISSION_DENIED` on `generateAccessToken`: the `roles/iam.workloadIdentityUser` binding is missing or the `subject` in the member does not match `sub`.
