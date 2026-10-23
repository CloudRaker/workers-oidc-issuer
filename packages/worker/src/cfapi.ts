/** Secrets Store REST calls. The bearer token is read by the caller (KeyRing.tick) and never logged. */
export type CfApi = {
  fetcher: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
  base: string;
  token: string;
  accountId: string;
  storeId: string;
  deadline?: number; // epoch ms; whole-tick budget shared by every call
};

export const CF_API_BASE = "https://api.cloudflare.com/client/v4";
// 10 s per call, clamped to the tick's shared deadline: up to three calls (PATCH, GET re-resolve, PATCH) cannot sum past
// the 30 s blockConcurrencyWhile limit.
const CF_API_TIMEOUT_MS = 10_000;

function secretsUrl(api: CfApi, suffix: string): string {
  return `${api.base}/accounts/${api.accountId}/secrets_store/stores/${api.storeId}/secrets${suffix}`;
}

async function call(api: CfApi, method: string, url: string, body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = { authorization: `Bearer ${api.token}`, accept: "application/json" };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  init.signal = AbortSignal.timeout(Math.max(1, Math.min(CF_API_TIMEOUT_MS, (api.deadline ?? Infinity) - Date.now())));
  try {
    const res = await api.fetcher.fetch(url, init);
    if (!res.ok) throw new Error(`secrets store ${method} failed: HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("secrets store ")) throw e;
    // Native fetch errors can carry the URL (account id, store id); rethrow a status-only message.
    const kind = e instanceof DOMException && e.name === "TimeoutError" ? "timeout" : "network";
    throw new Error(`secrets store ${method} failed: ${kind}`);
  }
}

export async function findSecretId(api: CfApi, name: string): Promise<string | null> {
  const json = (await call(api, "GET", secretsUrl(api, `?search=${encodeURIComponent(name)}&per_page=100`))) as { result?: { id?: string; name?: string }[] };
  const hit = (json.result ?? []).find((s) => s.name === name);
  return typeof hit?.id === "string" ? hit.id : null;
}

export async function writeSecret(api: CfApi, secretId: string, value: string): Promise<void> {
  await call(api, "PATCH", secretsUrl(api, `/${secretId}`), { value });
}
