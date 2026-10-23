import { isJwks, type Jwks } from "./jwks.js";

/** The signal also aborts res.json(), so a stalled body is covered; FlowView ignores Esc while a step runs. */
export async function fetchJson(url: string, timeoutMs = 10_000): Promise<unknown> {
  const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.json();
}

export async function fetchJwks(issuer: string, timeoutMs = 10_000): Promise<Jwks> {
  const j = await fetchJson(`${issuer}/.well-known/jwks.json`, timeoutMs);
  if (!isJwks(j)) throw new Error("JWKS has the wrong shape");
  return j;
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Fetches the JWKS (which also triggers the lazy tick) until `until` holds or the timeout passes; returns the last JWKS seen. */
export async function pollJwks(issuer: string, until: (j: Jwks) => boolean, timeoutMs: number, stepMs = 3000): Promise<Jwks | null> {
  const end = Date.now() + timeoutMs;
  let last: Jwks | null = null;
  for (;;) {
    try {
      last = await fetchJwks(issuer, Math.max(1_000, Math.min(10_000, end - Date.now()))); // one attempt never overshoots the budget
      if (until(last)) return last;
    } catch {
      // not deployed yet or transient; keep polling
    }
    if (Date.now() >= end) return last;
    await sleep(stepMs);
  }
}
