import { createExecutionContext, SELF, waitOnExecutionContext } from "cloudflare:test";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from "jose";
import { describe, expect, it } from "vitest";
import { issueToken } from "../src/jwt";
import { E, genJwk, get, ISSUER, manualEnv, onlyKids, privates, seed, spyConsole, type TestEnv } from "./helpers";

// AS_CONSUMER_A exercises props delivery through the real RPC path; issueToken() with a patched env exercises the rules.
const PROPS = { sub: "consumer-a", aud: ["sts.amazonaws.com", "https://vault.example"] };

describe("getToken", () => {
  it("RPC entrypoint receives deploy-time props and signs with the active key", async () => {
    // The real env has three OIDC_KEY_ bindings; an unseeded slot is a read failure, which fails closed.
    for (const kid of ["k0", "k1", "k2"] as const) await seed(E[`OIDC_KEY_${kid}`], JSON.stringify(await genJwk(kid)));
    const r = await E.AS_CONSUMER_A.getToken({ aud: "sts.amazonaws.com" });
    expect(r.kid).toBe("k0");
    const jwks = (await (await SELF.fetch(`${ISSUER}/.well-known/jwks.json`)).json()) as JSONWebKeySet;
    const { payload } = await jwtVerify(r.token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: "sts.amazonaws.com" });
    expect(payload.sub).toBe("consumer-a");
    // RPC promises are thenables from another context; settle them before asserting.
    expect(await E.AS_CONSUMER_A.getToken({ aud: "https://evil.example" }).then(() => "ok", (e: Error) => e.message)).toBe("audience not allowed");
  });
  it("verifies with jose against the served JWKS; kid == active; jti unique; nbf set", async () => {
    const spy = spyConsole();
    const e = await manualEnv();
    const k0 = await genJwk("k0");
    await seed(E.OIDC_KEY_k0, JSON.stringify(k0)); // the spy must know the real private values
    const ctx = createExecutionContext();
    const a = await issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" });
    const b = await issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" });
    await waitOnExecutionContext(ctx);
    const jwks = (await (await get(e, "/.well-known/jwks.json")).json()) as JSONWebKeySet;
    const { payload, protectedHeader } = await jwtVerify(a.token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: "sts.amazonaws.com", algorithms: ["RS256"] });
    expect(protectedHeader).toEqual({ alg: "RS256", typ: "JWT", kid: "k0" });
    expect(a.kid).toBe("k0");
    expect(payload.sub).toBe("consumer-a");
    expect(payload.nbf).toBe(payload.iat);
    expect(payload.exp).toBe((payload.iat as number) + 300);
    expect(a.expiresAt).toBe(payload.exp);
    expect(typeof payload.jti).toBe("string");
    expect(decodeProtectedHeader(b.token).kid).toBe("k0");
    expect((await jwtVerify(b.token, createLocalJWKSet(jwks))).payload.jti).not.toBe(payload.jti);
    expect(jwks.keys[0]!.n).toBe(k0.n); // the re-seeded key is the one served
    spy.done([...privates([k0]), a.token]);
  });
  it("aud must be an exact member of props.aud; bad props throw", async () => {
    const e = await manualEnv();
    const ctx = createExecutionContext();
    await expect(issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com " })).rejects.toThrow("audience not allowed");
    await expect(issueToken(e, ctx, PROPS, { aud: "https://evil.example" })).rejects.toThrow("audience not allowed");
    await expect(issueToken(e, ctx, PROPS, { aud: "" })).rejects.toThrow("invalid opts");
    // The second long-aud entry matters: validating only opts.aud would still reject ["x"*513] by accident ("audience not allowed") but accept it beside "a".
    for (const bad of [undefined, null, "x", { sub: "", aud: ["a"] }, { sub: "a\u0000", aud: ["a"] }, { sub: "x".repeat(256), aud: ["a"] }, { sub: "a", aud: [] }, { sub: "a", aud: [""] }, { sub: "a", aud: "a" }, { sub: "a", aud: ["x".repeat(513)] }, { sub: "a", aud: ["a", "x".repeat(513)] }]) {
      await expect(issueToken(e, ctx, bad, { aud: "a" })).rejects.toThrow("invalid props");
    }
    // Boundaries accepted: sub of exactly 255, aud entry of exactly 512.
    const max = { sub: "s".repeat(255), aud: ["a".repeat(512)] };
    await expect(issueToken(e, ctx, max, { aud: "a".repeat(512) })).resolves.toMatchObject({ kid: "k0" });
  });
  it("ttl: default 300, consumer can shorten, never lengthen, floor 60, integer only", async () => {
    const e = await manualEnv();
    const ctx = createExecutionContext();
    const ttl = async (o: { aud: string; ttl?: number }) => {
      const r = await issueToken(e, ctx, PROPS, o);
      const payload = JSON.parse(atob(r.token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { iat: number; exp: number };
      return payload.exp - payload.iat;
    };
    expect(await ttl({ aud: "sts.amazonaws.com" })).toBe(300);
    expect(await ttl({ aud: "sts.amazonaws.com", ttl: 120 })).toBe(120);
    expect(await ttl({ aud: "sts.amazonaws.com", ttl: 9999 })).toBe(300);
    expect(await ttl({ aud: "sts.amazonaws.com", ttl: 1 })).toBe(60);
    await expect(ttl({ aud: "sts.amazonaws.com", ttl: 1.5 })).rejects.toThrow("ttl");
    const long = { ...e, TOKEN_TTL_SECONDS: "3600" };
    expect((await issueToken(long, ctx, PROPS, { aud: "sts.amazonaws.com", ttl: 3600 })).expiresAt - Math.floor(Date.now() / 1000)).toBeGreaterThanOrEqual(3599);
  });
  it("TOKEN_TTL_SECONDS 7200 or abc is misconfigured; broken active key throws", async () => {
    const e = await manualEnv();
    const ctx = createExecutionContext();
    await expect(issueToken({ ...e, TOKEN_TTL_SECONDS: "7200" }, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("misconfigured");
    await expect(issueToken({ ...e, TOKEN_TTL_SECONDS: "abc" }, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("misconfigured");
    await expect(issueToken(await manualEnv({ OIDC_KEY_k0: { get: () => Promise.reject(new Error("transient")) } }), ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("keys unavailable");
    await seed(E.OIDC_KEY_k1, JSON.stringify({ ...(await genJwk("k1")), key_ops: ["sign"] }));
    const broken = { ...onlyKids(E as TestEnv, ["k0", "k1"]), ...e, OIDC_KEY_k1: E.OIDC_KEY_k1, ACTIVE_KID: "k1" };
    await expect(issueToken(broken, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("no active signing key");
  });
  it("two manual keys: both published, signed with the active one", async () => {
    const e = await manualEnv({}, ["k0", "k1"]);
    await seed(E.OIDC_KEY_k1, JSON.stringify(await genJwk("k1")));
    const both = { ...e, ACTIVE_KID: "k1" };
    const ctx = createExecutionContext();
    const r = await issueToken(both, ctx, PROPS, { aud: "https://vault.example" });
    expect(r.kid).toBe("k1");
    const jwks = (await (await get(both, "/.well-known/jwks.json")).json()) as JSONWebKeySet;
    expect(jwks.keys.map((k) => k.kid)).toEqual(["k1", "k0"]);
    await jwtVerify(r.token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: "https://vault.example" });
  });
  it("the deployed default export exposes no token route", async () => {
    for (const [p, m] of [["/token", "POST"], ["/getToken", "POST"], ["/.well-known/jwks.json", "POST"]] as const) {
      const r = await SELF.fetch(`https://oidc-issuer.example${p}`, { method: m });
      expect([404, 405]).toContain(r.status);
      expect(await r.text()).not.toContain("eyJ");
    }
  });
});
