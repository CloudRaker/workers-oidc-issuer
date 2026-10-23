import { describe, expect, it } from "vitest";
import { validateToken } from "../src/lib/cfapi.js";

const ACC = "0123456789abcdef0123456789abcdef";
const STORE = "fedcba9876543210fedcba9876543210";
const BASE = `https://api.cloudflare.com/client/v4/accounts/${ACC}/secrets_store/stores`;
type Call = { method: string; url: string; auth: string | null; body: string | null };
type Route = { status: number; body: unknown };
/** Routes by "METHOD path-suffix"; unmatched -> 404. */
const fetcher = (routes: Record<string, Route>, calls: Call[] = []) => ({
  fetch: (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({ method, url, auth: new Headers(init?.headers).get("authorization"), body: typeof init?.body === "string" ? init.body : null });
    const hit = Object.entries(routes).find(([k]) => k.split(" ")[0] === method && url.startsWith(`${BASE}${k.split(" ")[1]}`));
    return new Response(JSON.stringify(hit?.[1].body ?? {}), { status: hit?.[1].status ?? 404, headers: { "content-type": "application/json" } });
  }) as typeof fetch,
});
const STORES = { status: 200, body: { result: [{ id: STORE, name: "default" }] } };
const SECRETS = { status: 200, body: { result: [{ id: "sid", name: "OIDC_KEYSET" }] } };
const o = { accountId: ACC, storeId: STORE, token: "tok-123", keysetSecretName: "OIDC_KEYSET" };

describe("validateToken", () => {
  it("Edit token: lists the store, finds the keyset by name, PATCHes its scopes only (a live keyset keeps its value)", async () => {
    const calls: Call[] = [];
    const r = await validateToken(o, fetcher({ "GET ?per_page": STORES, [`GET /${STORE}/secrets?search=`]: SECRETS, [`PATCH /${STORE}/secrets/sid`]: { status: 200, body: { result: {} } } }, calls));
    expect(r).toEqual({ ok: true });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `GET ${BASE}?per_page=100`,
      `GET ${BASE}/${STORE}/secrets?search=OIDC_KEYSET&per_page=100`,
      `PATCH ${BASE}/${STORE}/secrets/sid`,
    ]);
    expect(calls.every((c) => c.auth === "Bearer tok-123")).toBe(true);
    expect(JSON.parse(calls[2]?.body ?? "{}")).toEqual({ scopes: ["workers"] });
  });
  it("Read-only token: reads pass, PATCH 403 -> needs Edit, not Read; never echoes the token", async () => {
    const r = await validateToken({ ...o, token: "SECRET-TOKEN" }, fetcher({ "GET ?per_page": STORES, [`GET /${STORE}/secrets?search=`]: SECRETS, [`PATCH /${STORE}/secrets/sid`]: { status: 403, body: { errors: [{ code: 10000 }] } } }));
    expect(r).toMatchObject({ ok: false, reason: expect.stringMatching(/Edit, not Read/) });
    expect(JSON.stringify(r)).not.toContain("SECRET-TOKEN");
  });
  it("store not visible / keyset secret missing from the search", async () => {
    expect(await validateToken(o, fetcher({ "GET ?per_page": { status: 200, body: { result: [{ id: "other" }] } } }))).toMatchObject({ ok: false, reason: expect.stringContaining("not visible") });
    expect(await validateToken(o, fetcher({ "GET ?per_page": STORES, [`GET /${STORE}/secrets?search=`]: { status: 200, body: { result: [{ id: "x", name: "OIDC_KEYSET_OLD" }] } } }))).toMatchObject({ ok: false, reason: expect.stringContaining("OIDC_KEYSET is not visible") });
  });
  it("401/403 on the first read and network errors never echo the token", async () => {
    const r = await validateToken({ ...o, token: "SECRET-TOKEN" }, fetcher({ "GET ?per_page": { status: 403, body: { errors: [{ code: 9109 }] } } }));
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain("SECRET-TOKEN");
    const n = await validateToken({ ...o, token: "SECRET-TOKEN" }, { fetch: (async () => { throw new Error("ECONNRESET"); }) as typeof fetch });
    expect(n).toMatchObject({ ok: false, reason: expect.stringContaining("network") });
    const tls = await validateToken({ ...o, token: "SECRET-TOKEN" }, { fetch: (async () => { throw new TypeError("fetch failed", { cause: Object.assign(new Error("unable to verify the first certificate"), { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }) }); }) as typeof fetch });
    expect(tls).toMatchObject({ ok: false, reason: expect.stringContaining("unable to verify the first certificate") });
    expect(JSON.stringify(tls)).not.toContain("SECRET-TOKEN");
  });
  it("every call carries a timeout signal", async () => {
    const signals: unknown[] = [];
    await validateToken(o, { fetch: (async (_u: string | URL | Request, init?: RequestInit) => { signals.push(init?.signal); return new Response("{}", { status: 500 }); }) as typeof fetch });
    expect(signals).toHaveLength(1);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
  });
});
