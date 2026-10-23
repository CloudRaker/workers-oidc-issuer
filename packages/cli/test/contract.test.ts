import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { enableAutoMode, enableManualMode, parseConfig, setIssuer } from "../src/lib/jsonc.js";

// Cross-package contract: the CLI's edits of the REAL packages/worker/wrangler.jsonc must produce exactly the vars and
// bindings packages/worker/src/config.ts validates (spec section 1, "Env validation"). Nothing is imported from the worker.
const real = readFileSync(new URL("../../worker/wrangler.jsonc", import.meta.url), "utf8");
const ACC = "0123456789abcdef0123456789abcdef";
const STORE = "fedcba9876543210fedcba9876543210";
const KID_RE = /^[a-z0-9]{1,32}$/;
const MANUAL_VARS = ["ACTIVE_KID", "ISSUER", "ROTATION", "TOKEN_TTL_SECONDS"];
const AUTO_VARS = ["CF_ACCOUNT_ID", "ISSUER", "KEYSET_SECRET_NAME", "RETIRE_KIDS", "REVOKE_BEFORE", "ROTATE_NONCE", "ROTATION", "ROTATION_GRACE_HOURS", "ROTATION_INTERVAL_HOURS", "SECRETS_STORE_ID", "TOKEN_TTL_SECONDS"];

type Cfg = ReturnType<typeof parseConfig> & { compatibility_flags?: string[]; migrations?: { new_sqlite_classes?: string[] }[]; cache?: unknown };

function expectCommon(c: Cfg): void {
  const v = c.vars ?? {};
  expect(v["ISSUER"]).toMatch(/^https:\/\/[^/?#]+$/);
  expect(Number(v["TOKEN_TTL_SECONDS"])).toBeGreaterThanOrEqual(60);
  expect(Number(v["TOKEN_TTL_SECONDS"])).toBeLessThanOrEqual(3600);
  expect(c.compatibility_flags).toEqual(["no_nodejs_compat", "no_nodejs_compat_v2", "disable_ctx_exports"]);
  expect(c.cache).toBeUndefined();
}

function expectManual(c: Cfg): void {
  expectCommon(c);
  const v = c.vars ?? {};
  expect(Object.keys(v).sort()).toEqual(MANUAL_VARS);
  expect(v["ROTATION"]).toBe("manual");
  const bindings = (c.secrets_store_secrets ?? []).map((b) => b.binding);
  const kids = bindings.filter((b) => b.startsWith("OIDC_KEY_")).map((b) => b.slice(9));
  expect(kids.length).toBe(bindings.length);
  expect(kids.length).toBeGreaterThanOrEqual(1);
  expect(kids.length).toBeLessThanOrEqual(10);
  for (const k of kids) expect(k).toMatch(KID_RE);
  expect(v["ACTIVE_KID"]).toMatch(KID_RE);
  expect(kids).toContain(v["ACTIVE_KID"]);
  for (const b of c.secrets_store_secrets ?? []) expect(b.secret_name).toBe(b.binding);
  expect(c.durable_objects).toBeUndefined();
  expect(c.triggers?.crons ?? []).toEqual([]);
}

function expectAuto(c: Cfg): void {
  expectCommon(c);
  const v = c.vars ?? {};
  expect(Object.keys(v).sort()).toEqual(AUTO_VARS);
  expect(v["ROTATION"]).toBe("auto");
  expect(v["CF_ACCOUNT_ID"]).toMatch(/^[0-9a-f]{32}$/);
  expect(v["SECRETS_STORE_ID"]).toMatch(/^[0-9a-f]{32}$/);
  expect(v["KEYSET_SECRET_NAME"]).toMatch(/^[A-Za-z0-9_]{1,64}$/);
  const interval = Number(v["ROTATION_INTERVAL_HOURS"]);
  const grace = Number(v["ROTATION_GRACE_HOURS"]);
  expect(v["ROTATION_INTERVAL_HOURS"]).toMatch(/^\d+$/);
  expect(v["ROTATION_GRACE_HOURS"]).toMatch(/^\d+$/);
  expect(interval).toBeGreaterThanOrEqual(24);
  expect(interval).toBeLessThanOrEqual(8760);
  expect(grace).toBeGreaterThanOrEqual(2);
  expect(grace).toBeLessThanOrEqual(168);
  expect(grace).toBeLessThan(interval / 2);
  expect(v["REVOKE_BEFORE"]).toBe("");
  expect(v["ROTATE_NONCE"]!.length).toBeLessThanOrEqual(64);
  expect(JSON.parse(v["RETIRE_KIDS"]!)).toEqual([]);
  expect(c.secrets_store_secrets).toEqual([
    { binding: "OIDC_KEYSET", store_id: v["SECRETS_STORE_ID"], secret_name: v["KEYSET_SECRET_NAME"] },
    { binding: "CF_API_TOKEN", store_id: v["SECRETS_STORE_ID"], secret_name: "OIDC_CF_API_TOKEN" },
  ]);
  expect(c.durable_objects).toEqual({ bindings: [{ name: "KEYRING", class_name: "KeyRing" }] });
  expect(c.migrations?.some((m) => m.new_sqlite_classes?.includes("KeyRing"))).toBe(true);
  expect(c.triggers?.crons).toEqual(["17 * * * *"]);
}

describe("wrangler.jsonc contract with packages/worker/src/config.ts", () => {
  it("the shipped file is valid manual mode once ISSUER is set", () => {
    const shipped = parseConfig(real) as Cfg;
    expect(shipped.vars?.["ISSUER"]).toBe("https://PENDING");
    expect(shipped.secrets_store_secrets).toEqual([{ binding: "OIDC_KEY_k0", store_id: "REPLACE_ME", secret_name: "OIDC_KEY_k0" }]);
    expectManual(parseConfig(setIssuer(real, "https://oidc.example.com")) as Cfg);
  });
  it("enableAutoMode on the real file yields exactly the auto-mode env", () => {
    const auto = enableAutoMode(setIssuer(real, "https://oidc.example.com"), { accountId: ACC, storeId: STORE });
    expectAuto(parseConfig(auto) as Cfg);
    expect(auto).toContain("// no_nodejs_compat*");
  });
  it("enableManualMode after auto yields exactly the manual-mode env", () => {
    const auto = enableAutoMode(setIssuer(real, "https://oidc.example.com"), { accountId: ACC, storeId: STORE });
    const manual = enableManualMode(auto, { storeId: STORE, kid: "k20261022beef" });
    const c = parseConfig(manual) as Cfg;
    expectManual(c);
    expect(c.vars?.["ACTIVE_KID"]).toBe("k20261022beef");
    expect(c.secrets_store_secrets).toEqual([{ binding: "OIDC_KEY_k20261022beef", store_id: STORE, secret_name: "OIDC_KEY_k20261022beef" }]);
    expect(c.triggers).toEqual({ crons: [] }); // an absent key would leave the deployed hourly cron in place
    expect(parseConfig(setIssuer(real, "https://oidc.example.com")).triggers).toBeUndefined();
  });
});
