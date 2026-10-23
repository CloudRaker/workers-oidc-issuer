import { describe, expect, it } from "vitest";
import pkg from "../package.json";
import cfapi from "../src/cfapi.ts?raw";
import config from "../src/config.ts?raw";
import index from "../src/index.ts?raw";
import jwt from "../src/jwt.ts?raw";
import keyring from "../src/keyring.ts?raw";
import keys from "../src/keys.ts?raw";
import pub from "../src/public.ts?raw";
import testConfig from "./wrangler.jsonc?raw";
import shipped from "../wrangler.jsonc?raw";

describe("static", () => {
  it("package.json has no runtime dependencies", () => {
    expect(pkg).not.toHaveProperty("dependencies");
  });
  it("nothing references ctx.exports", () => {
    for (const src of [index, pub, jwt, keys, keyring, cfapi, config]) expect(src).not.toContain("ctx.exports");
  });
  it("the fetch path imports no signer", () => {
    expect(pub).not.toMatch(/from "\.\/jwt/);
    expect(pub).not.toMatch(/subtle\.sign|issueToken|signJwt/);
    expect(index).toMatch(/export \{ default \} from "\.\/public\.js"/);
  });
  it("CF_API_TOKEN is read only inside KeyRing.tick (hardening 13)", () => {
    for (const src of [index, pub, jwt, keys, cfapi]) expect(src).not.toContain("CF_API_TOKEN");
    expect(config).not.toMatch(/CF_API_TOKEN[^\n]*\.get\(/); // config only checks the binding exists (type + hasMethod)
    expect(keyring.match(/CF_API_TOKEN[^\n]*\.get\(/g)).toHaveLength(1);
    expect(keyring.indexOf("async tick(")).toBeLessThan(keyring.search(/CF_API_TOKEN[^\n]*\.get\(/));
  });
  it("wrangler.jsonc ships manual mode with the hardening flags; the test runtime differs by disable_ctx_exports and by nodejs_compat_v2 (plugin strips no_nodejs_compat_v2)", () => {
    for (const f of ["no_nodejs_compat", "no_nodejs_compat_v2", "disable_ctx_exports"]) expect(shipped).toContain(`"${f}"`);
    expect(shipped).toContain('"ROTATION": "manual"');
    expect(shipped).not.toContain('"cache"');
    expect(testConfig).toContain('"compatibility_date": "2026-10-13"');
    // @cloudflare/vitest-plugin removes no_nodejs_compat_v2 from the runner, so tests run WITH Node globals. The only guard for production is scripts/lint-bundle.mjs.
    expect(typeof (globalThis as Record<string, unknown>)["Buffer"]).toBe("function");
    expect(testConfig).not.toMatch(/"disable_ctx_exports"/);
  });
});
