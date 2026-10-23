import type { Issuer } from "../../../packages/worker/src/index";

interface Env {
  OIDC: Service<Issuer>;
  ANTHROPIC_ORGANIZATION_ID: string;
  ANTHROPIC_FEDERATION_RULE_ID: string;
  ANTHROPIC_SERVICE_ACCOUNT_ID: string;
  ANTHROPIC_WORKSPACE_ID: string;
  ANTHROPIC_MODEL: string;
}

const API = "https://api.anthropic.com";
const AUD = "https://api.anthropic.com";

type TokenResponse = { access_token: string; token_type: string; expires_in: number; scope?: string };

/** Exchange an issuer JWT for a short-lived Anthropic access token (RFC 7523 jwt-bearer). The JWT travels only in the POST body. */
export async function exchange(jwt: string, env: Omit<Env, "OIDC" | "ANTHROPIC_MODEL">): Promise<TokenResponse> {
  const res = await fetch(`${API}/v1/oauth/token`, {
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
  if (!res.ok) {
    // Status and request id only. Never the body, never the JWT. The deny reason is in the
    // Claude Console authentication history; the API answers every denial with the same 401.
    console.error(`anthropic exchange: status=${res.status} request-id=${res.headers.get("request-id") ?? "none"}`);
    throw new Error("anthropic exchange failed");
  }
  return (await res.json()) as TokenResponse;
}

// ponytail: one service account per Worker, so one module-scope slot.
let cached: { token: string; expiresAt: number } | null = null;

/**
 * A cached Anthropic access token. Each exchange asks the issuer for a NEW JWT: Anthropic accepts a
 * given jti only once, so a JWT is never reused, not even on retry.
 */
export async function accessToken(env: Env, now = Date.now()): Promise<string> {
  if (cached && now < cached.expiresAt - 60_000) return cached.token;
  const { token: jwt } = await env.OIDC.getToken({ aud: AUD });
  const t = await exchange(jwt, env);
  cached = { token: t.access_token, expiresAt: now + t.expires_in * 1000 };
  return t.access_token;
}

export function resetCache() {
  cached = null;
}

export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    const token = await accessToken(env);
    const res = await fetch(`${API}/v1/messages`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: env.ANTHROPIC_MODEL,
        max_tokens: 256,
        messages: [{ role: "user", content: "Say hello from a Cloudflare Worker with no API key." }],
      }),
    });
    return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
  },
} satisfies ExportedHandler<Env>;
