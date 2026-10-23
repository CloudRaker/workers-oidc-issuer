import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  addSecretBinding, bindingKids, enableAutoMode, enableManualMode, parseConfig, removeSecretBinding,
  setAccountId, setActiveKid, setIssuer, setVar, summarize,
} from "../src/lib/jsonc.js";

const src = readFileSync(new URL("./fixtures/wrangler.jsonc", import.meta.url), "utf8");
const ACC = "0123456789abcdef0123456789abcdef";
const STORE = "fedcba9876543210fedcba9876543210";

function expectPreserved(t: string): void {
  expect(t).toContain("// no_nodejs_compat*: signer uses WebCrypto only.");
  expect(t).toContain("// REQUIRED https origin");
  expect(parseConfig(t)).toMatchObject({
    compatibility_flags: ["no_nodejs_compat", "no_nodejs_compat_v2", "disable_ctx_exports"],
    preview_urls: false,
    observability: { enabled: true },
  });
}

describe("jsonc edits", () => {
  it("setVar / setIssuer / setActiveKid", () => {
    let t = setVar(src, "TOKEN_TTL_SECONDS", "600");
    t = setIssuer(t, "https://oidc.example.com");
    t = setActiveKid(t, "k20261022abcd");
    expect(parseConfig(t).vars).toEqual({ ISSUER: "https://oidc.example.com", ROTATION: "manual", ACTIVE_KID: "k20261022abcd", TOKEN_TTL_SECONDS: "600" });
    expectPreserved(t);
    expect(t).toMatchSnapshot();
  });
  it("setAccountId sits after compatibility_flags and survives other edits", () => {
    let t = setAccountId(src, ACC);
    expect(t.indexOf('"account_id"')).toBeGreaterThan(t.indexOf('"compatibility_flags"'));
    expect(t.indexOf('"account_id"')).toBeLessThan(t.indexOf('"preview_urls"'));
    t = setIssuer(addSecretBinding(t, { binding: "OIDC_KEY_k1", store_id: STORE, secret_name: "OIDC_KEY_k1" }), "https://a.example");
    expect(parseConfig(t).account_id).toBe(ACC);
    expectPreserved(t);
    expect(t).toMatchSnapshot();
  });
  it("add/remove secret binding", () => {
    let t = addSecretBinding(src, { binding: "OIDC_KEY_k1", store_id: STORE, secret_name: "OIDC_KEY_k1" });
    expect(bindingKids(parseConfig(t))).toEqual(["k0", "k1"]);
    t = addSecretBinding(t, { binding: "OIDC_KEY_k0", store_id: STORE, secret_name: "OIDC_KEY_k0" }); // replace placeholder store id
    expect(parseConfig(t).secrets_store_secrets).toEqual([
      { binding: "OIDC_KEY_k0", store_id: STORE, secret_name: "OIDC_KEY_k0" },
      { binding: "OIDC_KEY_k1", store_id: STORE, secret_name: "OIDC_KEY_k1" },
    ]);
    t = removeSecretBinding(t, "OIDC_KEY_k0");
    expect(bindingKids(parseConfig(t))).toEqual(["k1"]);
    expect(removeSecretBinding(t, "NOPE")).toBe(t);
    expectPreserved(t);
    expect(t).toMatchSnapshot();
  });
  it("enableAutoMode then enableManualMode", () => {
    const auto = enableAutoMode(setAccountId(src, ACC), { accountId: ACC, storeId: STORE });
    const a = parseConfig(auto);
    expect(a.vars).toEqual({
      ISSUER: "https://PENDING", ROTATION: "auto", TOKEN_TTL_SECONDS: "300", CF_ACCOUNT_ID: ACC, SECRETS_STORE_ID: STORE,
      KEYSET_SECRET_NAME: "OIDC_KEYSET", ROTATION_INTERVAL_HOURS: "720", ROTATION_GRACE_HOURS: "24", ROTATE_NONCE: "", REVOKE_BEFORE: "", RETIRE_KIDS: "[]",
    });
    expect(a.secrets_store_secrets).toEqual([
      { binding: "OIDC_KEYSET", store_id: STORE, secret_name: "OIDC_KEYSET" },
      { binding: "CF_API_TOKEN", store_id: STORE, secret_name: "OIDC_CF_API_TOKEN" },
    ]);
    expect(a).toMatchObject({
      account_id: ACC,
      durable_objects: { bindings: [{ name: "KEYRING", class_name: "KeyRing" }] },
      migrations: [{ tag: "v1", new_sqlite_classes: ["KeyRing"] }],
      triggers: { crons: ["17 * * * *"] },
    });
    expectPreserved(auto);
    expect(summarize(auto)).toMatchObject({ mode: "auto", storeId: STORE, accountId: ACC, kids: [] });
    expect(auto).toMatchSnapshot();

    const manual = enableManualMode(auto, { storeId: STORE, kid: "k20261022abcd" });
    const m = parseConfig(manual);
    expect(m.vars).toEqual({ ISSUER: "https://PENDING", ROTATION: "manual", TOKEN_TTL_SECONDS: "300", ACTIVE_KID: "k20261022abcd" });
    expect(m.secrets_store_secrets).toEqual([{ binding: "OIDC_KEY_k20261022abcd", store_id: STORE, secret_name: "OIDC_KEY_k20261022abcd" }]);
    expect(m.durable_objects).toBeUndefined();
    expect(m.triggers).toEqual({ crons: [] }); // empty list clears the deployed cron; an absent key would keep it
    expect(m).toHaveProperty("migrations"); // history is never rewritten
    expect(m.account_id).toBe(ACC);
    expectPreserved(manual);
    expect(summarize(manual)).toEqual({ mode: "manual", issuer: "https://PENDING", activeKid: "k20261022abcd", kids: ["k20261022abcd"], accountId: ACC, storeId: STORE, name: "oidc-issuer" });
    expect(manual).toMatchSnapshot();
  });
  it("enableAutoMode re-run keeps policy vars", () => {
    const auto = enableAutoMode(setAccountId(src, ACC), { accountId: ACC, storeId: STORE });
    let t = setVar(auto, "ROTATE_NONCE", "abc");
    t = setVar(t, "ROTATION_INTERVAL_HOURS", "2160");
    t = setVar(t, "ROTATION_GRACE_HOURS", "72");
    const v = parseConfig(enableAutoMode(t, { accountId: ACC, storeId: STORE })).vars;
    expect(v).toMatchObject({ ROTATE_NONCE: "abc", ROTATION_INTERVAL_HOURS: "2160", ROTATION_GRACE_HOURS: "72", ROTATION: "auto" });
  });
  it("enableManualMode without a kid keeps ACTIVE_KID absent and adds no OIDC_KEY_ binding", () => {
    const auto = enableAutoMode(setAccountId(src, ACC), { accountId: ACC, storeId: STORE });
    const m = parseConfig(enableManualMode(auto, { storeId: STORE }));
    expect(m.vars).toEqual({ ISSUER: "https://PENDING", ROTATION: "manual", TOKEN_TTL_SECONDS: "300" });
    expect(m.secrets_store_secrets ?? []).toEqual([]);
    expect(m.durable_objects).toBeUndefined();
  });
  it("summarize on the shipped defaults", () => {
    expect(summarize(src)).toEqual({ mode: "manual", issuer: "https://PENDING", activeKid: "k0", kids: ["k0"], accountId: undefined, storeId: "REPLACE_ME", name: "oidc-issuer" });
  });
});
