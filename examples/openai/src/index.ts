import type { Issuer } from "../../../packages/worker/src/index";

interface Env {
  OIDC: Service<Issuer>;
  OPENAI_IDENTITY_PROVIDER_ID: string;
  OPENAI_SERVICE_ACCOUNT_ID: string;
}

const AUD = "https://api.openai.com";

type TokenResponse = { access_token: string; token_type: string; expires_in: number; expires_at: number; scope?: string };

/** Exchange an issuer JWT for a short-lived OpenAI access token (RFC 8693 token exchange). The JWT travels only in the POST body. */
export async function exchange(jwt: string, env: Omit<Env, "OIDC">): Promise<TokenResponse> {
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
  if (!res.ok) {
    // Status only. Never the body, never the JWT.
    console.error(`openai exchange: status=${res.status}`);
    throw new Error("openai exchange failed");
  }
  return (await res.json()) as TokenResponse;
}

// ponytail: one service account per Worker, so one module-scope slot.
let cached: { token: string; expiresAt: number } | null = null;

/** A cached OpenAI access token (at most 1 hour). A fresh issuer JWT per exchange. */
export async function accessToken(env: Env, now = Date.now()): Promise<string> {
  if (cached && now < cached.expiresAt - 60_000) return cached.token;
  const { token: jwt } = await env.OIDC.getToken({ aud: AUD });
  const t = await exchange(jwt, env);
  cached = { token: t.access_token, expiresAt: t.expires_at * 1000 };
  return t.access_token;
}

export function resetCache() {
  cached = null;
}

export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    const token = await accessToken(env);
    // Smoke test: list models. Swap for /v1/responses in real code.
    const res = await fetch("https://api.openai.com/v1/models", {
      headers: { authorization: `Bearer ${token}` },
    });
    return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
  },
} satisfies ExportedHandler<Env>;
