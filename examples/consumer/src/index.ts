import type { Issuer } from "../../../packages/worker/src/index";

interface Env {
  OIDC: Service<Issuer>;
  AWS_REGION: string;
  AWS_ROLE_ARN: string;
}

export interface AwsCredentials {
  AccessKeyId: string;
  SecretAccessKey: string;
  SessionToken: string;
  Expiration: string; // ISO-8601
}

type StsResponse = {
  AssumeRoleWithWebIdentityResponse?: {
    AssumeRoleWithWebIdentityResult?: { Credentials?: AwsCredentials };
  };
};

const AUD = "sts.amazonaws.com";

/** Exchange an issuer token for AWS credentials. The token travels only in the POST body. */
export async function assumeRole(
  token: string,
  env: Pick<Env, "AWS_REGION" | "AWS_ROLE_ARN">,
): Promise<AwsCredentials> {
  const body = new URLSearchParams({
    Action: "AssumeRoleWithWebIdentity",
    Version: "2011-06-15",
    RoleArn: env.AWS_ROLE_ARN,
    RoleSessionName: "example-consumer",
    WebIdentityToken: token,
    DurationSeconds: "900",
  });
  const res = await fetch(`https://sts.${env.AWS_REGION}.amazonaws.com/`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body,
  });
  if (!res.ok) {
    // Log status and AWS error code only. Never the body, never the token.
    const err = (await res.json().catch(() => null)) as { Error?: { Code?: string } } | null;
    console.error(`sts: status=${res.status} code=${err?.Error?.Code ?? "unknown"}`);
    throw new Error("sts exchange failed");
  }
  const json = (await res.json()) as StsResponse;
  const creds = json.AssumeRoleWithWebIdentityResponse?.AssumeRoleWithWebIdentityResult?.Credentials;
  if (!creds) throw new Error("sts: no credentials in response");
  return creds;
}

// ponytail: one role per Worker, so one module-scope slot; key by role ARN if you add more.
let cached: { creds: AwsCredentials; expiresAt: number } | null = null;

export async function getCredentials(env: Env): Promise<AwsCredentials> {
  if (cached && Date.now() < cached.expiresAt - 60_000) return cached.creds;
  const { token } = await env.OIDC.getToken({ aud: AUD });
  const creds = await assumeRole(token, env);
  cached = { creds, expiresAt: Date.parse(creds.Expiration) };
  return creds;
}

export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    const creds = await getCredentials(env);
    // Use creds to sign AWS requests. This example returns only the non-secret parts.
    return Response.json({ accessKeyId: creds.AccessKeyId, expiration: creds.Expiration });
  },
} satisfies ExportedHandler<Env>;
