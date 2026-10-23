import { createExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { issueToken } from "../src/jwt";
import { autoEnv, get, ISSUER, manualEnv, spyConsole } from "./helpers";

/** Spec: content-type, nosniff and HSTS on every response; cache only on 200; no CORS. */
function hardened(res: Response, status: number, msg?: string) {
  expect(res.status, msg).toBe(status);
  expect(res.headers.get("content-type"), msg).toBe("application/json; charset=utf-8");
  expect(res.headers.get("x-content-type-options"), msg).toBe("nosniff");
  expect(res.headers.get("strict-transport-security"), msg).toBe("max-age=31536000");
  expect(res.headers.get("cache-control"), msg).toBe(status === 200 ? "public, max-age=3600" : "no-store");
  expect(res.headers.get("access-control-allow-origin"), msg).toBeNull();
}

describe("public routes", () => {
  it("discovery has the spec shape and issuer/jwks_uri from ISSUER only", async () => {
    const e = await manualEnv();
    const res = await get(e, "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      response_types_supported: ["id_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      claims_supported: ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"],
      scopes_supported: ["openid"],
    });
  });
  it("issuer never derives from the request host", async () => {
    const e = await manualEnv();
    const { createExecutionContext } = await import("cloudflare:test");
    const worker = (await import("../src/index")).default;
    const res = await worker.fetch(new Request("https://evil.example/.well-known/openid-configuration?x=1"), e, createExecutionContext());
    const j = (await res.json()) as { issuer: string; jwks_uri: string };
    expect(j.issuer).toBe(ISSUER);
    expect(j.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
  });
  it("jwks serves the public allow-list only", async () => {
    const e = await manualEnv();
    const res = await get(e, "/.well-known/jwks.json?ignored=1");
    expect(res.status).toBe(200);
    const j = (await res.json()) as { keys: Record<string, unknown>[] };
    expect(j.keys).toHaveLength(1);
    expect(Object.keys(j.keys[0]!).sort()).toEqual(["alg", "e", "kid", "kty", "n", "use"]);
    expect(j.keys[0]).toMatchObject({ kid: "k0", kty: "RSA", alg: "RS256", use: "sig" });
  });
  it("headers: json, nosniff, hsts, cache only on 200, no cors", async () => {
    const e = await manualEnv();
    hardened(await get(e, "/.well-known/jwks.json"), 200);
    hardened(await get(e, "/token"), 404);
  });
  it("HEAD works, other methods get 405 with Allow", async () => {
    const e = await manualEnv();
    const head = await get(e, "/.well-known/jwks.json", { method: "HEAD" });
    hardened(head, 200);
    expect(await head.text()).toBe("");
    const post = await get(e, "/.well-known/jwks.json", { method: "POST", body: "{}" });
    hardened(post, 405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
    expect(await post.text()).not.toContain("eyJ");
    for (const p of ["/getToken", "/token", "/", "/.well-known/jwks.json/"]) {
      const r = await get(e, p, { method: "POST" });
      hardened(r, 404, p);
      expect(await r.text()).not.toContain("eyJ");
    }
  });
  it("misconfiguration is a 500 that echoes nothing, in body or logs", async () => {
    const spy = spyConsole();
    const overs = [{ ISSUER: "http://oidc.example.com" }, { ISSUER: "https://oidc.example.com/path" }, { ISSUER: "https://PENDING" }, { TOKEN_TTL_SECONDS: "7200" }, { TOKEN_TTL_SECONDS: "abc" }, { ROTATION: "weird" }, { ACTIVE_KID: "k9" }, { ACTIVE_KID: "K0" }];
    for (const over of overs) {
      const e = await manualEnv(over);
      const res = await get(e, "/.well-known/jwks.json");
      hardened(res, 500, JSON.stringify(over));
      const body = await res.text();
      expect(body).toBe('{"error":"misconfigured"}');
    }
    // Config values never reach logs (hardening item 5); one var-name-only warning per case.
    const out = spy.done(overs.flatMap((o) => Object.values(o)));
    expect(out.match(/^misconfigured: [A-Z_*]+ /gm)).toHaveLength(overs.length);
  });
  it("auto-mode misconfiguration is a 500 that echoes nothing; boundaries pass", async () => {
    const spy = spyConsole();
    const overs: Record<string, unknown>[] = [
      { CF_ACCOUNT_ID: "0123456789abcdef0123456789abcdeZ" }, { SECRETS_STORE_ID: "0".repeat(31) },
      { KEYSET_SECRET_NAME: "bad-name" }, { KEYSET_SECRET_NAME: "n".repeat(65) },
      { ROTATION_INTERVAL_HOURS: "23" }, { ROTATION_INTERVAL_HOURS: "8761" }, { ROTATION_INTERVAL_HOURS: "7.5" },
      { ROTATION_GRACE_HOURS: "1" }, { ROTATION_GRACE_HOURS: "169" },
      // grace must be < interval/2: these hit that check, not the [2,168] range (grace 360 would fail the range first).
      { ROTATION_INTERVAL_HOURS: "48", ROTATION_GRACE_HOURS: "24" }, { ROTATION_INTERVAL_HOURS: "336", ROTATION_GRACE_HOURS: "168" },
      { REVOKE_BEFORE: "yesterday" }, { REVOKE_BEFORE: "2026-10-22" }, { REVOKE_BEFORE: "2026-13-45T00:00:00Z" },
      // Calendar-invalid: V8's Date.parse rolls these forward, which would silently shift the revoke cutoff.
      { REVOKE_BEFORE: "2026-02-30T00:00:00Z" }, { REVOKE_BEFORE: "2026-01-01T24:00:00Z" }, { REVOKE_BEFORE: "2027-02-29T00:00:00Z" },
      { RETIRE_KIDS: "k1" }, { RETIRE_KIDS: '["K1"]' }, { RETIRE_KIDS: '{"k1":1}' },
      { ROTATE_NONCE: "x".repeat(65) },
      { KEYRING: undefined }, { CF_API_TOKEN: undefined }, { OIDC_KEYSET: undefined }, { KEYRING: {} },
    ];
    const PROPS = { sub: "consumer-a", aud: ["sts.amazonaws.com"] };
    for (const over of overs) {
      const e = autoEnv(over);
      const res = await get(e, "/.well-known/jwks.json");
      hardened(res, 500, JSON.stringify(over));
      expect(await res.text()).toBe('{"error":"misconfigured"}');
      await expect(issueToken(e, createExecutionContext(), PROPS, { aud: "sts.amazonaws.com" }), JSON.stringify(over)).rejects.toThrow("misconfigured");
    }
    // Discovery runs parseConfig only: no keyset, DO or tick involved, so no seeding is needed for a 200.
    for (const ok of [{ ROTATION_INTERVAL_HOURS: "48", ROTATION_GRACE_HOURS: "23" }, { ROTATION_INTERVAL_HOURS: "24", ROTATION_GRACE_HOURS: "2" }, { ROTATION_INTERVAL_HOURS: "8760", ROTATION_GRACE_HOURS: "168" }, { REVOKE_BEFORE: "2026-10-22T00:00:00Z" }, { REVOKE_BEFORE: "2024-02-29T00:00:00Z" }, { REVOKE_BEFORE: "2026-10-22T13:45:00.123+05:30" }, { RETIRE_KIDS: '["k1"]' }]) {
      expect((await get(autoEnv(ok), "/.well-known/openid-configuration")).status, JSON.stringify(ok)).toBe(200);
    }
    // Values never reach logs. Plain integers are skipped: the range text ("[2, 168]") legitimately contains them.
    const vals = overs.flatMap((o) => Object.values(o).filter((v): v is string => typeof v === "string" && !/^\d+$/.test(v)));
    const out = spy.done(vals);
    expect(out.match(/^misconfigured: [A-Z_]+ /gm)).toHaveLength(overs.length); // fetch path warns once per case; issueToken throws silently
  });
  it("a Secrets Store read failure is a 500 with no-store, not an empty cacheable JWKS", async () => {
    const spy = spyConsole();
    const e = await manualEnv({ OIDC_KEY_k0: { get: () => Promise.reject(new Error("transient")) } });
    for (const method of ["GET", "HEAD"]) {
      const res = await get(e, "/.well-known/jwks.json", { method });
      hardened(res, 500, method);
      expect(await res.text()).toBe(method === "HEAD" ? "" : '{"error":"unavailable"}');
    }
    expect(spy.done(["transient"])).toContain("keys unavailable");
  });
});
