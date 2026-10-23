import { describe, expect, it } from "vitest";
import { importPrivate, parsePrivateJwk, publicJwk, type PrivateJwk } from "../src/keys";
import { E, genJwk, get, manualEnv, onlyKids, privates, seed, spyConsole } from "./helpers";

describe("key material rules", () => {
  it("exact member set; extra members reject", async () => {
    const jwk = await genJwk("k1");
    expect(parsePrivateJwk(jwk)).not.toBeNull();
    for (const extra of [{ oth: [] }, { key_ops: ["sign"] }, { ext: true }, { x5c: [] }]) expect(parsePrivateJwk({ ...jwk, ...extra })).toBeNull();
    const { d: _d, ...missing } = jwk;
    expect(parsePrivateJwk(missing)).toBeNull();
    expect(parsePrivateJwk({ ...jwk, alg: "RS512" })).toBeNull();
    expect(parsePrivateJwk({ ...jwk, use: "enc" })).toBeNull();
    expect(parsePrivateJwk({ ...jwk, kid: "K1" })).toBeNull();
    expect(parsePrivateJwk({ ...jwk, n: "not*base64url" })).toBeNull();
  });
  it("public JWK is an allow-list", async () => {
    const pub = publicJwk(parsePrivateJwk(await genJwk("k1")) as PrivateJwk);
    expect(Object.keys(pub).sort()).toEqual(["alg", "e", "kid", "kty", "n", "use"]);
  });
  it("import is non-extractable; 1024-bit keys are rejected by modulusLength", async () => {
    const ok = await importPrivate(parsePrivateJwk(await genJwk("k1")) as PrivateJwk);
    expect(ok?.extractable).toBe(false);
    expect(await importPrivate(parsePrivateJwk(await genJwk("k1", 1024)) as PrivateJwk)).toBeNull();
  });
  it("private members that do not sign for (n, e) are rejected at import", async () => {
    const a = await genJwk("k1");
    const b = await genJwk("k1");
    // A d-only swap still signs through the CRT path; swap every private member.
    const mixed = { ...a, d: b.d, p: b.p, q: b.q, dp: b.dp, dq: b.dq, qi: b.qi };
    expect(await importPrivate(parsePrivateJwk(mixed) as PrivateJwk)).toBeNull();
    expect(await importPrivate(parsePrivateJwk(a) as PrivateJwk)).toBeInstanceOf(CryptoKey);
  });
  it("broken non-active slots are omitted; inner kid must match the binding; logs carry kids only", async () => {
    const k1 = await genJwk("k1");
    const zz = await genJwk("zz");
    // Both seeded JWKs are real secrets: the k2 slot is a valid key with a mismatched inner kid.
    const secrets = privates([k1, zz]);
    const spy = spyConsole(secrets);
    const e = await manualEnv({}, ["k0", "k1", "k2"]);
    await seed(E.OIDC_KEY_k1, JSON.stringify({ ...k1, oth: [] }));
    await seed(E.OIDC_KEY_k2, JSON.stringify(zz));
    const res = await get(e, "/.well-known/jwks.json");
    const j = (await res.json()) as { keys: { kid: string }[] };
    expect(j.keys.map((k) => k.kid)).toEqual(["k0"]);
    expect(spy.warn).toHaveBeenCalledWith("key slot broken: kid=k1");
    expect(spy.warn).toHaveBeenCalledWith("key slot broken: kid=k2");
    spy.done();
  });
  it("two manual keys publish both, active first; broken active still serves the others", async () => {
    const e = await manualEnv({}, ["k0", "k1", "k2"]);
    await seed(E.OIDC_KEY_k1, JSON.stringify(await genJwk("k1")));
    const both = onlyKids(e, ["k0", "k1"]);
    expect(((await (await get(both, "/.well-known/jwks.json")).json()) as { keys: { kid: string }[] }).keys.map((k) => k.kid)).toEqual(["k0", "k1"]);
    const swapped = { ...both, ACTIVE_KID: "k1" };
    expect(((await (await get(swapped, "/.well-known/jwks.json")).json()) as { keys: { kid: string }[] }).keys.map((k) => k.kid)).toEqual(["k1", "k0"]);
    await seed(E.OIDC_KEY_k2, "not json");
    const broken = { ...onlyKids(e, ["k0", "k2"]), ACTIVE_KID: "k2" };
    const res = await get(broken, "/.well-known/jwks.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(((await res.json()) as { keys: { kid: string }[] }).keys.map((k) => k.kid)).toEqual(["k0"]);
  });
  it("eleven bindings or a bad suffix is a misconfiguration", async () => {
    const e = await manualEnv();
    const many = { ...e } as Record<string, unknown>;
    for (let i = 3; i <= 12; i++) many[`OIDC_KEY_k${i}`] = e.OIDC_KEY_k0;
    expect((await get(many as typeof e, "/.well-known/jwks.json")).status).toBe(500);
    const bad = { ...e, OIDC_KEY_Bad: e.OIDC_KEY_k0 } as unknown as typeof e;
    expect((await get(bad, "/.well-known/jwks.json")).status).toBe(500);
  });
});
