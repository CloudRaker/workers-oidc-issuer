import { describe, expect, it } from "vitest";
import { buildJwksTable, fingerprint, formatAge, isJwks } from "../src/lib/jwks.js";
import { verifyChecks, verifyPassed } from "../src/lib/verify.js";

const ISS = "https://oidc.example.com";
const key = (kid: string) => ({ kty: "RSA", n: `n-${kid}`, e: "AQAB", kid, alg: "RS256", use: "sig" });
const discovery = {
  issuer: ISS, jwks_uri: `${ISS}/.well-known/jwks.json`, response_types_supported: ["id_token"], subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"], claims_supported: ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"], scopes_supported: ["openid"],
};

describe("verifyChecks", () => {
  it("manual: all pass", () => {
    const c = verifyChecks({ issuer: ISS, discovery, jwks: { keys: [key("k1"), key("k0")] }, expectedKids: ["k0", "k1"], activeKid: "k1", targets: ["oidc.example.com/*", "https://x.acme.workers.dev"] });
    expect(c.filter((x) => !x.ok)).toEqual([]);
    expect(verifyPassed(c)).toBe(true);
  });
  it("issuer derived from request fails; missing kid fails; target mismatch only warns", () => {
    const c = verifyChecks({ issuer: ISS, discovery: { ...discovery, issuer: "https://evil.example" }, jwks: { keys: [key("k1")] }, expectedKids: ["k0", "k1"], activeKid: "k1", targets: ["https://x.acme.workers.dev"] });
    const byName = Object.fromEntries(c.map((x) => [x.name, x]));
    expect(byName["discovery.issuer"]?.ok).toBe(false);
    expect(byName["jwks.bindings"]).toMatchObject({ ok: false, detail: "missing k0" });
    expect(byName["deploy.target"]).toMatchObject({ ok: false, warn: true });
    expect(verifyPassed(c)).toBe(false);
    expect(verifyPassed(c.filter((x) => x.name === "deploy.target"))).toBe(true);
  });
  it("auto: shape + non-empty", () => {
    const c = verifyChecks({ issuer: ISS, discovery, jwks: { keys: [] } });
    expect(c.find((x) => x.name === "jwks.nonEmpty")?.ok).toBe(false);
    expect(verifyChecks({ issuer: ISS, discovery, jwks: "nope" }).find((x) => x.name === "jwks.shape")?.ok).toBe(false);
  });
});

describe("jwks table", () => {
  it("fingerprint = base64url(sha256(n.e))", () => {
    expect(fingerprint({ n: "abc", e: "AQAB" })).toBe("4ZWW3KA8woXgU2iAH9VUzYiI36lLXf1t_0DqEGCiK0c");
    expect(fingerprint({ n: "abc", e: "AQAB" })).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it("roles, age from kid timestamp", () => {
    const now = Date.UTC(2026, 9, 25, 5); // 2026-10-25T05:00Z
    const rows = buildJwksTable({ keys: [key("k1792645200aaaa"), key("k20261022bbbb"), key("k0"), key("k1")] }, now); // 2026-10-22T05:00Z
    expect(rows.map((r) => r.role)).toEqual(["active", "retiring", "published", "published"]); // k20261022bbbb is 2026-10-22T00:00Z: older than active
    expect(rows[0]?.age).toBe("3d");
    expect(rows[1]?.age).toBe("3d");
    expect(rows[2]?.age).toBe("?");
    expect(rows[0]?.fp).toBe(fingerprint(key("k1792645200aaaa")));
  });
  it("role comes from age relative to the active key, not from position", () => {
    const now = Date.parse("2026-10-22T05:00:00Z");
    // [active, retiring] after a promotion: the older key must not be labelled next (Rotate now would refuse for the whole grace window)
    expect(buildJwksTable({ keys: [key("k1792645200aaaa"), key("k1792040400bbbb")] }, now).map((r) => r.role)).toEqual(["active", "retiring"]);
    // [active, next] before a promotion
    expect(buildJwksTable({ keys: [key("k1792645200aaaa"), key("k1792648800cccc")] }, now).map((r) => r.role)).toEqual(["active", "next"]);
    // kids without a timestamp stay "published"
    expect(buildJwksTable({ keys: [key("k1792645200aaaa"), key("k0")] }, now).map((r) => r.role)).toEqual(["active", "published"]);
  });
  it("formatAge", () => {
    expect(formatAge(59_000)).toBe("0m");
    expect(formatAge(-5_000)).toBe("0m");
    expect(formatAge(5 * 3_600_000)).toBe("5h");
    expect(formatAge(49 * 3_600_000)).toBe("2d");
  });
  it("isJwks", () => {
    expect(isJwks({ keys: [] })).toBe(true);
    expect(isJwks({ keys: [{ kid: "k" }] })).toBe(false);
    expect(isJwks(null)).toBe(false);
  });
});
