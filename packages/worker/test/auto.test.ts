import { adminSecretsStore, createExecutionContext, createScheduledController, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { writeSecret } from "../src/cfapi";
import type { Policy } from "../src/config";
import worker from "../src/index";
import { issueToken } from "../src/jwt";
import type { KeyRing, TickReport } from "../src/keyring";
import { autoEnv, E, genJwk, get, ISSUER, privates, seed, spyConsole, type TestEnv } from "./helpers";

const H = 3600;
// Far future (2096). kids() routes through worker.fetch -> scheduleTick, which can fire a real-clock tick against
// the same DO rows; every injected-now event must stay ahead of the real clock so that tick is a no-op.
// kids() must also pass the ROTATE_NONCE / REVOKE_BEFORE the DO last recorded, otherwise the lazy tick sees a policy change.
const T0 = 4_000_000_000;
const POLICY: Policy = { intervalHours: 720, graceHours: 24, rotateNonce: "", revokeBefore: "", retireKids: [] };
const EMPTY = '{"v":1,"version":0,"active":"","keys":[]}';
const PROPS = { sub: "consumer-a", aud: ["sts.amazonaws.com"] };
let keysetId = "";

const stub = () => E.KEYRING.get(E.KEYRING.idFromName("default"));
const tick = (p: Partial<Policy> = {}, now?: number): Promise<TickReport> => stub().tick({ ...POLICY, ...p }, now);
const captured = async (): Promise<string> => (await E.CF_API.fetch("https://fake/__captured")).text();
/** Simulates Secrets Store propagation of the last PATCH. */
async function mirror(): Promise<string> {
  const v = await captured();
  using admin = adminSecretsStore(E.OIDC_KEYSET);
  await admin.update(v, keysetId);
  return v;
}
const kids = async (e = autoEnv()): Promise<string[]> => ((await (await get(e, "/.well-known/jwks.json")).json()) as { keys: { kid: string }[] }).keys.map((k) => k.kid);
const rows = () => runInDurableObject(stub(), (_i: KeyRing, state) => state.storage.sql.exec<{ kid: string; status: string }>("SELECT kid, status FROM keys ORDER BY created").toArray());
const meta = (k: string) => runInDurableObject(stub(), (_i: KeyRing, state) => state.storage.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0]?.v);
/** Every column of both tables: "nothing persisted" means nothing. */
const dump = () => runInDurableObject(stub(), (_i: KeyRing, state) => JSON.stringify([state.storage.sql.exec("SELECT * FROM keys ORDER BY kid").toArray(), state.storage.sql.exec("SELECT * FROM meta ORDER BY k").toArray()]));
/** RPC promises are thenables from another context; settle them before asserting. */
const settled = (p: Promise<unknown>): Promise<string> => p.then(() => "ok", (e: Error) => e.message);
const toggle = (what: "fail" | "hang", on: boolean) => E.CF_API.fetch(`https://fake/__${what}`, { method: "POST", body: on ? "on" : "off" });

// Storage isolation is per test file (vitest-plugin 1.x), so each test resets what it depends on.
beforeAll(async () => {
  keysetId = await seed(E.OIDC_KEYSET, EMPTY);
  await seed(E.CF_API_TOKEN, "test-api-token");
});
beforeEach(async () => {
  await E.CF_API.fetch("https://fake/__reset", { method: "POST" });
  using admin = adminSecretsStore(E.OIDC_KEYSET);
  await admin.update(EMPTY, keysetId);
  await runInDurableObject(stub(), (i: KeyRing, state) => {
    state.storage.sql.exec("DELETE FROM keys; DELETE FROM meta");
    (i as unknown as { lastFail: unknown }).lastFail = null; // in-memory write backoff
  });
});

describe("auto mode", () => {
  it("bootstrap tick creates an active key, PATCHes the keyset, JWKS serves it, getToken verifies", async () => {
    const spy = spyConsole();
    const r0 = await tick();
    expect(r0.changed).toBe(true);
    expect(r0.kids).toHaveLength(1);
    expect(r0.kids[0]!.status).toBe("active");
    expect(JSON.stringify(r0)).not.toContain('"d":');
    const ks = JSON.parse(await mirror()) as { version: number; active: string; keys: Record<string, string>[] };
    expect(ks.version).toBe(1);
    expect(ks.active).toBe(r0.kids[0]!.kid);
    expect(await meta("secret_id")).toBe("sec1"); // exact-name match: the fake lists the OIDC_KEYSET_OLD decoy (sec2) first
    expect(await kids()).toEqual([ks.active]);
    const ctx = createExecutionContext();
    const t = await issueToken(autoEnv(), ctx, PROPS, { aud: "sts.amazonaws.com" });
    await waitOnExecutionContext(ctx);
    expect(t.kid).toBe(ks.active);
    const jwks = (await (await get(autoEnv(), "/.well-known/jwks.json")).json()) as JSONWebKeySet;
    await jwtVerify(t.token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: "sts.amazonaws.com" });
    expect((await tick()).changed).toBe(false);
    spy.done(privates(ks.keys));
  });
  it("empty keyset: JWKS is empty and not cacheable, getToken fails closed, the lazy tick self-heals", async () => {
    const e = autoEnv({ ROTATE_NONCE: "heal-1" });
    const empty = await get(e, "/.well-known/jwks.json");
    expect(empty.headers.get("cache-control")).toBe("no-store");
    expect(await empty.json()).toEqual({ keys: [] });
    const ctx = createExecutionContext();
    await expect(issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("no active signing key");
    await waitOnExecutionContext(ctx);
    const ks = JSON.parse(await mirror()) as { active: string };
    expect(ks.active).not.toBe("");
    expect(await kids(e)).toEqual([ks.active]);
  });
  it("provenance: a foreign key (valid JWK, unknown fp) is dropped; a foreign active fails closed and is regenerated", async () => {
    await tick();
    const ks = JSON.parse(await mirror()) as { version: number; active: string; keys: Record<string, unknown>[] };
    const fkid = "k1700000000beef";
    const foreign = { ...(await genJwk(fkid)), created: 1700000000, status: "next" };
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update(JSON.stringify({ ...ks, keys: [...ks.keys, foreign] }), keysetId);
    expect(await kids()).toEqual([ks.active]);
    await admin.update(JSON.stringify({ ...ks, active: fkid, keys: [{ ...foreign, status: "active" }] }), keysetId);
    const e = autoEnv({ ROTATE_NONCE: "prov-2" });
    expect(await kids(e)).toEqual([]);
    const ctx = createExecutionContext();
    await expect(issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("no active signing key");
    await waitOnExecutionContext(ctx);
    const next = JSON.parse(await mirror()) as { active: string; keys: { kid: string }[] };
    expect(next.keys.map((k) => k.kid)).not.toContain(fkid);
    expect(next.active).not.toBe(fkid);
    expect(await kids(e)).toEqual([next.active]);
  });
  it("scheduled rotation: next at interval-grace, promoted at activateAt, old retired after grace", async () => {
    const r0 = await tick({}, T0);
    const k0 = r0.kids[0]!.kid;
    await mirror();
    expect((await tick({}, T0 + (720 - 24) * H - 1)).kids.map((k) => k.status)).toEqual(["active"]);
    const r1 = await tick({}, T0 + (720 - 24) * H);
    expect(r1.kids.map((k) => k.status)).toEqual(["active", "next"]);
    const k1 = r1.kids[1]!;
    expect(k1.activateAt).toBe(T0 + 720 * H);
    await mirror();
    expect(await kids()).toEqual([k0, k1.kid]);
    const r2 = await tick({}, T0 + 720 * H);
    expect(r2.kids.map((k) => [k.kid, k.status])).toEqual([[k0, "retiring"], [k1.kid, "active"]]);
    expect(r2.kids[0]!.retireAt).toBe(T0 + 744 * H);
    await mirror();
    expect(await kids()).toEqual([k1.kid, k0]);
    const r3 = await tick({}, T0 + 744 * H);
    expect(r3.kids.map((k) => k.kid)).toEqual([k1.kid]);
    await mirror();
    expect(await kids()).toEqual([k1.kid]);
    expect((await rows()).map((r) => r.status)).toEqual(["deleted", "active"]);
  });
  it("rotateNonce change starts a graceful rotation; revokeBefore removes old keys on the same tick", async () => {
    const k0 = (await tick({}, T0)).kids[0]!.kid;
    await mirror();
    const r1 = await tick({ rotateNonce: "abcd1234" }, T0 + 10);
    expect(r1.kids.map((k) => k.status)).toEqual(["active", "next"]);
    expect(r1.kids[1]!.activateAt).toBe(T0 + 10 + 24 * H);
    await mirror();
    expect((await tick({ rotateNonce: "abcd1234" }, T0 + 20)).changed).toBe(false);
    const revokeBefore = new Date((T0 + 100) * 1000).toISOString();
    const r2 = await tick({ rotateNonce: "abcd1234", revokeBefore }, T0 + 100);
    expect(r2.kids).toHaveLength(1);
    expect(r2.kids[0]!.status).toBe("active");
    expect(r2.kids[0]!.kid).not.toBe(k0);
    await mirror();
    expect(await kids(autoEnv({ ROTATE_NONCE: "abcd1234", REVOKE_BEFORE: revokeBefore }))).toEqual([r2.kids[0]!.kid]);
    expect((await tick({ rotateNonce: "abcd1234", revokeBefore }, T0 + 200)).changed).toBe(false);
  });
  it("retireKids retires a non-active kid and ignores the active one with a warning", async () => {
    const k0 = (await tick({}, T0)).kids[0]!.kid;
    await mirror();
    const r1 = await tick({ rotateNonce: "n1" }, T0 + 1);
    const k1 = r1.kids[1]!.kid;
    await mirror();
    const r2 = await tick({ rotateNonce: "n1", retireKids: [k0, k1] }, T0 + 2);
    expect(r2.warnings).toContainEqual(`retire ignored for active key: kid=${k0}`);
    expect(r2.kids.map((k) => k.kid)).toEqual([k0]);
    await mirror();
    expect(await kids(autoEnv({ ROTATE_NONCE: "n1" }))).toEqual([k0]);
  });
  it("API failure persists nothing", async () => {
    const k0 = (await tick({}, T0)).kids[0]!.kid;
    await mirror();
    const before = { dump: await dump(), keyset: await captured() };
    const revokeBefore = new Date((T0 + 100) * 1000).toISOString();
    await toggle("fail", true);
    expect(await settled(tick({ rotateNonce: "boom" }, T0 + 10))).toBe("secrets store PATCH failed: HTTP 500");
    expect(await settled(tick({ rotateNonce: "boom", revokeBefore }, T0 + 100))).toBe("secrets store PATCH failed: HTTP 500");
    expect(await dump()).toBe(before.dump);
    expect(await captured()).toBe(before.keyset);
    await toggle("fail", false);
    // last_nonce was not persisted: the same nonce still starts a rotation.
    expect((await tick({ rotateNonce: "boom" }, T0 + 200)).kids).toHaveLength(2);
    await mirror();
    // last_revoke_before was not persisted: the same marker still revokes k0.
    const r = await tick({ rotateNonce: "boom", revokeBefore }, T0 + 300);
    expect(r.kids.map((k) => k.kid)).not.toContain(k0);
  });
  it("a failed lazy tick logs the status only (spec 1.5, hardening 5)", async () => {
    await tick();
    await mirror();
    const spy = spyConsole();
    await toggle("fail", true);
    const e = autoEnv({ ROTATE_NONCE: "logfail" });
    await get(e, "/.well-known/jwks.json");
    await toggle("fail", false);
    const out = spy.done([e.CF_ACCOUNT_ID as string, e.SECRETS_STORE_ID as string, "sec1"]);
    expect(out).toContain("tick failed: secrets store PATCH failed: HTTP 500");
  });
  it("getToken alone schedules the lazy tick on a policy change (spec: fetch handler AND getToken)", async () => {
    const k0 = (await tick()).kids[0]!.kid;
    await mirror();
    // No get()/kids() first: that would set lastTick with this fingerprint and mask a missing scheduleTick in issueToken.
    const e = autoEnv({ ROTATE_NONCE: "rpc-only" });
    const ctx = createExecutionContext();
    const t = await issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" });
    await waitOnExecutionContext(ctx);
    expect(t.kid).toBe(k0); // signs with the current active; the nonce only adds a `next`
    expect(await meta("last_nonce")).toBe("rpc-only");
    expect((await rows()).map((r) => r.status).sort()).toEqual(["active", "next"]);
  });
  it("every API call is clamped to the tick deadline, not the 10 s per-call timeout", async () => {
    const fetcher = { fetch: (_u: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_, rej) => init!.signal!.addEventListener("abort", () => rej(init!.signal!.reason))) };
    const api = { fetcher, base: "https://fake", token: "t", accountId: "a", storeId: "s", deadline: Date.now() + 500 };
    const t0 = Date.now();
    await expect(writeSecret(api, "sec1", "v")).rejects.toThrow("secrets store PATCH failed: timeout");
    expect(Date.now() - t0).toBeLessThan(5_000);
  });
  it("a failed write backs off for 60 s with no API call; a policy change bypasses the backoff", async () => {
    await tick({}, T0);
    await mirror();
    await toggle("fail", true);
    expect(await settled(tick({ rotateNonce: "bo" }, T0 + 10))).toMatch(/HTTP 500/);
    await toggle("fail", false);
    const written = await captured();
    const r = await tick({ rotateNonce: "bo" }, T0 + 20);
    expect(r).toMatchObject({ changed: false, warnings: ["tick backoff"] });
    expect(r.kids).toHaveLength(1);
    expect(await captured()).toBe(written);
    expect((await tick({ rotateNonce: "bo2" }, T0 + 21)).kids).toHaveLength(2);
    await mirror();
    expect((await tick({ rotateNonce: "bo" }, T0 + 70)).warnings).toEqual([]);
  });
  it("a failed OIDC_KEYSET read aborts the tick and persists nothing", async () => {
    await tick();
    await mirror();
    const before = { dump: await dump(), keyset: await captured() };
    const env = await runInDurableObject(stub(), (inst: KeyRing) => {
      const i = inst as unknown as { env: Record<string, unknown> };
      const original = i.env;
      Object.defineProperty(i, "env", { value: { ...original, OIDC_KEYSET: { get: () => Promise.reject(new Error("secrets store unavailable")) } }, configurable: true, writable: true });
      return original;
    });
    try {
      expect(await settled(tick({ rotateNonce: "readfail" }))).toBe("secrets store unavailable");
    } finally {
      await runInDurableObject(stub(), (inst: KeyRing) => { Object.defineProperty(inst, "env", { value: env, configurable: true, writable: true }); });
    }
    expect(await dump()).toBe(before.dump);
    expect(await captured()).toBe(before.keyset);
  });
  it("a stale cached secret_id is re-resolved by name", async () => {
    await tick();
    await mirror();
    await runInDurableObject(stub(), (_i: KeyRing, state) => { state.storage.sql.exec("UPDATE meta SET v = 'gone' WHERE k = 'secret_id'"); });
    expect((await tick({ rotateNonce: "re" })).kids).toHaveLength(2);
    expect(await meta("secret_id")).toBe("sec1");
  });
  it("a hung PATCH times out inside the DO and persists nothing", { timeout: 15_000 }, async () => {
    await tick();
    await mirror();
    const before = { dump: await dump(), keyset: await captured() };
    await toggle("hang", true);
    expect(await settled(tick({ rotateNonce: "hang" }))).toBe("secrets store PATCH failed: timeout");
    await toggle("hang", false);
    expect(await dump()).toBe(before.dump);
    expect(await captured()).toBe(before.keyset);
  });
  it("a tick inside the propagation window keeps the rows; a keyset still behind after the window is regenerated", async () => {
    const r0 = await tick({}, T0);
    const k0 = r0.kids[0]!;
    // Not mirrored: the binding still serves the EMPTY document (version 0 < meta 1).
    const r1 = await tick({}, T0 + 1);
    expect(r1.changed).toBe(false);
    expect(r1.warnings).toContain("keyset behind the DO; waiting for propagation");
    expect(r1.kids).toEqual(r0.kids);
    expect(await rows()).toEqual([{ kid: k0.kid, status: "active" }]);
    expect(await stub().confirm([{ kid: k0.kid, fp: k0.fp }])).toEqual([{ kid: k0.kid, status: "active" }]);
    expect((JSON.parse(await captured()) as { version: number }).version).toBe(1);
    // Unreadable (empty) value inside the window: same answer.
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update("", keysetId);
    expect(await tick({}, T0 + 2)).toMatchObject({ changed: false, warnings: ["keyset behind the DO; waiting for propagation"] });
    await mirror();
    expect(await tick({}, T0 + 3)).toMatchObject({ changed: false, warnings: [] });
    // Still behind once the window has passed: that is a real loss, regenerate.
    await admin.update(EMPTY, keysetId);
    const r = await tick({}, T0 + 60);
    expect(r.changed).toBe(true);
    expect(r.kids).toHaveLength(1);
    expect(r.kids[0]!.kid).not.toBe(k0.kid);
  });
  it("a keyset with a version behind the DO is rewritten once the propagation window has passed", async () => {
    await tick({}, T0);
    const v1 = await mirror();
    const r1 = await tick({ rotateNonce: "x" }, T0 + 1);
    const v2 = await mirror();
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update(v1, keysetId);
    const w = await tick({ rotateNonce: "x" }, T0 + 2);
    expect(w.changed).toBe(false);
    expect(w.kids.map((k) => k.kid)).toEqual(r1.kids.map((k) => k.kid));
    expect(await captured()).toBe(v2);
    const r = await tick({ rotateNonce: "x" }, T0 + 61);
    expect(r.changed).toBe(true);
    expect(r.warnings).toContain("keyset version behind; rewriting");
    expect((JSON.parse(await captured()) as { version: number }).version).toBe(3);
  });
  it("same material with an edited version is rewritten and keeps the next kid", async () => {
    await tick({}, T0);
    await mirror();
    const r1 = await tick({ rotateNonce: "x" }, T0 + 1);
    const v2 = JSON.parse(await mirror()) as { version: number };
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update(JSON.stringify({ ...v2, version: 1 }), keysetId);
    const r = await tick({ rotateNonce: "x" }, T0 + 61);
    expect(r.changed).toBe(true);
    expect(r.kids.map((k) => [k.kid, k.status])).toEqual(r1.kids.map((k) => [k.kid, k.status]));
    expect((JSON.parse(await captured()) as { version: number }).version).toBe(3);
  });
  it("a tampered active (same version) is ignored by the signer and repaired by the next tick", async () => {
    const k0 = (await tick({}, T0)).kids[0]!.kid;
    await mirror();
    const k1 = (await tick({ rotateNonce: "t" }, T0 + 1)).kids[1]!.kid;
    const v2 = JSON.parse(await mirror()) as { version: number; active: string };
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update(JSON.stringify({ ...v2, active: k1 }), keysetId);
    const r = await tick({ rotateNonce: "t" }, T0 + 2);
    expect(r.changed).toBe(true);
    expect(r.warnings).toContain("keyset differs from DO state; rewriting");
    expect(JSON.parse(await captured())).toMatchObject({ version: 3, active: k0 });
    // The binding still serves the tampered value: the signer follows the DO's status, not the keyset's `active`.
    const e = autoEnv({ ROTATE_NONCE: "t" });
    expect(await kids(e)).toEqual([k0, k1]);
    const ctx = createExecutionContext();
    expect((await issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" })).kid).toBe(k0);
    await waitOnExecutionContext(ctx);
  });
  it("tampered private members of the active fail closed and are regenerated on the next tick", async () => {
    const k0 = (await tick({}, T0)).kids[0]!.kid;
    const v1 = JSON.parse(await mirror()) as { keys: Record<string, unknown>[] };
    const o = await genJwk("zz");
    // (n, e, kid) unchanged so the fp pin matches; every private member belongs to another key.
    const bad = { ...v1, keys: v1.keys.map((k) => ({ ...k, d: o.d, p: o.p, q: o.q, dp: o.dp, dq: o.dq, qi: o.qi })) };
    using admin = adminSecretsStore(E.OIDC_KEYSET);
    await admin.update(JSON.stringify(bad), keysetId);
    const e = autoEnv();
    expect(await kids(e)).toEqual([]);
    const ctx = createExecutionContext();
    await expect(issueToken(e, ctx, PROPS, { aud: "sts.amazonaws.com" })).rejects.toThrow("no active signing key");
    await waitOnExecutionContext(ctx);
    const r = await tick({}, T0 + 2);
    expect(r.changed).toBe(true);
    expect(r.warnings).toContain(`dropped unknown or unusable key: kid=${k0}`);
    expect(r.kids.map((k) => k.kid)).not.toContain(k0);
    expect(r.kids.filter((k) => k.status === "active")).toHaveLength(1);
    expect((JSON.parse(await captured()) as { keys: { d: string }[] }).keys[0]!.d).not.toBe(o.d);
  });
  it("a policy event that lands inside the propagation window is retried at the heal cadence, not per request", async () => {
    const k0 = (await tick()).kids[0]!.kid;
    let ticks = 0;
    const counting = {
      idFromName: (n: string) => E.KEYRING.idFromName(n),
      get: (id: DurableObjectId) => {
        const s = E.KEYRING.get(id);
        return { confirm: (x: { kid: string; fp: string }[]) => s.confirm(x), tick: (p: Policy) => { ticks++; return s.tick(p); } };
      },
    };
    // Not mirrored: the DO sees the keyset behind its version and skips the revoke.
    const e = autoEnv({ REVOKE_BEFORE: new Date(Date.now() + 1000).toISOString(), KEYRING: counting });
    await get(e, "/.well-known/jwks.json");
    await get(e, "/.well-known/jwks.json");
    expect(ticks).toBe(1); // the second request inside the window rides the 10 s heal gate
    expect(await rows()).toEqual([{ kid: k0, status: "active" }]);
    expect(await meta("last_revoke_before")).toBeUndefined();
    await mirror();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 11_000);
    try {
      await get(e, "/.well-known/jwks.json");
    } finally {
      vi.useRealTimers();
    }
    expect(ticks).toBe(2);
    const after = await rows();
    expect(after.find((r) => r.kid === k0)?.status).toBe("deleted");
    expect(after.filter((r) => r.status === "active")).toHaveLength(1);
    expect(await meta("last_revoke_before")).toBe(e.REVOKE_BEFORE);
  });
  it("a Secrets Store read failure on the signer is a 500 with no-store, not an empty cacheable JWKS", async () => {
    await tick();
    await mirror();
    const spy = spyConsole();
    const e = { ...autoEnv(), OIDC_KEYSET: { get: () => Promise.reject(new Error("transient")) } } as unknown as TestEnv;
    const res = await get(e, "/.well-known/jwks.json");
    expect(res.status).toBe(500);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).toBe('{"error":"unavailable"}');
    expect(spy.done(["transient"])).toContain("keys unavailable");
  });
  it("the fetch and signing paths never read CF_API_TOKEN (hardening 13)", async () => {
    await tick();
    await mirror();
    const trap = { ...autoEnv(), CF_API_TOKEN: { get: () => Promise.reject(new Error("token read outside tick")) } } as unknown as TestEnv;
    expect(await kids(trap)).toHaveLength(1);
    const ctx = createExecutionContext();
    const t = await issueToken(trap, ctx, PROPS, { aud: "sts.amazonaws.com" });
    await waitOnExecutionContext(ctx);
    expect(t.kid).toBeTruthy();
  });
  it("a KeyRing RPC failure is a 500 with the hardening headers and no-store", async () => {
    await tick();
    await mirror();
    const spy = spyConsole();
    const e = { ...autoEnv(), KEYRING: { idFromName: () => "x", get: () => ({ confirm: () => Promise.reject(new Error("overloaded")) }) } } as unknown as TestEnv;
    for (const method of ["GET", "HEAD"]) {
      const res = await get(e, "/.well-known/jwks.json", { method });
      expect(res.status).toBe(500);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(await res.text()).toBe(method === "HEAD" ? "" : '{"error":"unavailable"}');
    }
    expect(spy.done(["overloaded"])).toContain("keys unavailable");
  });
  it("scheduled handler ticks in auto mode and no-ops in manual mode", async () => {
    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController({ cron: "17 * * * *" }), autoEnv(), ctx);
    await waitOnExecutionContext(ctx);
    expect((await captured()).length).toBeGreaterThan(10);
    await E.CF_API.fetch("https://fake/__reset", { method: "POST" });
    await seed(E.OIDC_KEY_k0, JSON.stringify(await genJwk("k0")));
    await worker.scheduled(createScheduledController(), { ...E, ISSUER, ROTATION: "manual", ACTIVE_KID: "k0" } as TestEnv, ctx);
    await waitOnExecutionContext(ctx);
    expect((await E.CF_API.fetch("https://fake/__captured")).status).toBe(404);
  });
  it("DO storage never contains private material; the API token is never logged", async () => {
    const spy = spyConsole();
    await tick();
    await mirror();
    await tick({ rotateNonce: "q" });
    const sql = await runInDurableObject(stub(), (_i: KeyRing, state) => JSON.stringify([...state.storage.sql.exec("SELECT * FROM keys").toArray(), ...state.storage.sql.exec("SELECT * FROM meta").toArray()]));
    const kv = JSON.stringify([...(await runInDurableObject(stub(), (_i: KeyRing, state) => state.storage.list())).entries()]);
    const ks = JSON.parse(await captured()) as { keys: Record<string, string>[] };
    expect(ks.keys.length).toBeGreaterThan(1); // the fixture really carries private JWKs
    // Exact values: JSON.stringify would escape a keyset stored as a string column, which a `"d":` regex misses.
    for (const k of ks.keys) {
      for (const m of ["d", "p", "q", "dp", "dq", "qi"] as const) {
        expect(k[m]!.length).toBeGreaterThan(100);
        expect(sql).not.toContain(k[m]);
        expect(kv).not.toContain(k[m]);
      }
    }
    expect(sql).not.toMatch(/"d":|"p":|"q":|test-api-token/);
    expect(sql).toContain('"fp":');
    expect(kv).not.toContain("test-api-token");
    spy.done(privates(ks.keys));
  });
});
