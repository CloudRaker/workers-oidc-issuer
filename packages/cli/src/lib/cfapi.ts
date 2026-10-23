import { redact } from "./wrangler.js";

export const CF_API = "https://api.cloudflare.com/client/v4";
export const EMPTY_KEYSET = '{"v":1,"version":0,"active":"","keys":[]}';

export type TokenCheck = { ok: true } | { ok: false; reason: string };

/**
 * Validates an API token the way KeyRing.tick will use it: list stores, find the keyset secret by name, PATCH it.
 * The PATCH only re-asserts the `workers` scope, so a live keyset keeps its value on a Setup re-run. Never logs the token.
 */
export async function validateToken(
  o: { accountId: string; storeId: string; token: string; keysetSecretName: string },
  fetcher: { fetch: typeof fetch } = globalThis,
  base = CF_API,
): Promise<TokenCheck> {
  const headers: Record<string, string> = { authorization: `Bearer ${o.token}`, accept: "application/json" };
  let netErr = "";
  const call = async (url: string, init?: RequestInit): Promise<Response | null> => {
    try { return await fetcher.fetch(url, { ...init, signal: AbortSignal.timeout(10_000), headers: { ...headers, ...((init?.headers as Record<string, string>) ?? {}) } }); }
    catch (e) {
      // ponytail: undici wraps the socket error in TypeError("fetch failed").cause; that message is the useful one
      const c = e instanceof Error && e.cause instanceof Error ? e.cause : e;
      netErr = redact(String(c instanceof Error ? c.message || (c as { code?: string }).code || c.name : c)).slice(0, 200);
      return null;
    }
  };
  const netReason = () => `network error reaching api.cloudflare.com${netErr ? `: ${netErr}` : ""}`;
  const json = async (res: Response): Promise<unknown> => { try { return await res.json(); } catch { return undefined; } };
  const acct = `${base}/accounts/${o.accountId}/secrets_store/stores`;

  let res = await call(`${acct}?per_page=100`);
  if (!res) return { ok: false, reason: netReason() };
  if (res.status === 401 || res.status === 403) return { ok: false, reason: `token rejected (HTTP ${res.status}); it needs Account > Secrets Store > Edit on this account` };
  if (!res.ok) return { ok: false, reason: `unexpected HTTP ${res.status}` };
  let body = await json(res);
  if (body === undefined) return { ok: false, reason: "non-JSON response" };
  const stores = (body as { result?: { id?: unknown }[] }).result;
  if (!Array.isArray(stores) || !stores.some((s) => s.id === o.storeId)) return { ok: false, reason: `token works but store ${o.storeId} is not visible to it` };

  res = await call(`${acct}/${o.storeId}/secrets?search=${encodeURIComponent(o.keysetSecretName)}&per_page=100`);
  if (!res) return { ok: false, reason: netReason() };
  if (!res.ok) return { ok: false, reason: `could not list secrets (HTTP ${res.status})` };
  body = await json(res);
  if (body === undefined) return { ok: false, reason: "non-JSON response" };
  const hit = ((body as { result?: { id?: unknown; name?: unknown }[] }).result ?? []).find((s) => s.name === o.keysetSecretName);
  if (typeof hit?.id !== "string") return { ok: false, reason: `secret ${o.keysetSecretName} is not visible to the token` };

  res = await call(`${acct}/${o.storeId}/secrets/${hit.id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ scopes: ["workers"] }) });
  if (!res) return { ok: false, reason: netReason() };
  if (res.status === 401 || res.status === 403) return { ok: false, reason: `token can read but cannot write secrets (HTTP ${res.status}); it needs Account > Secrets Store > Edit, not Read` };
  if (!res.ok) return { ok: false, reason: `unexpected HTTP ${res.status} on write probe` };
  return { ok: true };
}
