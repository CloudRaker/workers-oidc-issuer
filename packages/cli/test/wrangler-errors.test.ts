import { describe, expect, it } from "vitest";
import { mapWranglerError } from "../src/lib/wrangler-errors.js";

describe("mapWranglerError", () => {
  const cases: [string, string, string][] = [
    ["secrets-store store create default --remote", "✘ [ERROR] A request to the Cloudflare API failed. Authentication error [code: 10000]\n  authorization", "secrets-store-role"],
    ["secrets-store secret create X --name Y", "✘ [ERROR] 403 Forbidden", "secrets-store-role"],
    ["deploy", "✘ [ERROR] failed to fetch secrets store binding due to authorization error", "deploy-secrets-role"],
    ["secrets-store secret create X", "✘ [ERROR] You have reached the limit of 100 secrets for this account", "secret-limit"],
    ["secrets-store secret create X --name OIDC_KEYSET", "✘ [ERROR] A request to the Cloudflare API failed. Secret with this name already exists in this account [code: 10021]", "secret-exists"],
    ["deploy", "You need to register a workers.dev subdomain before deploying", "workers-dev"],
    ["deploy", "✘ [ERROR] More than one account available but unable to select one in non-interactive mode.", "multi-account"],
    ["whoami --json", "Could not authenticate because no credentials were found and the environment is non-interactive.", "login"],
    ["deploy", "something else entirely", "unknown"],
  ];
  it.each(cases)("%s: %s -> %s", (cmd, out, kind) => {
    const m = mapWranglerError(cmd, out);
    expect(m.kind).toBe(kind);
    expect(m.raw).toBe(out);
    expect(m.message.length).toBeGreaterThan(5);
  });
  it("raw shown under the hint is redacted", () => {
    const out = `403 authorization\n{"kty":"RSA","d":"SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRET","n":"x"}\nAuthorization: Bearer ${"A".repeat(40)}`;
    const m = mapWranglerError("wrangler secrets-store secret create", out);
    expect(m.kind).toBe("secrets-store-role");
    expect(m.raw).not.toContain("SECRETSECRET");
    expect(m.raw).toContain('"d":"[redacted]"');
    expect(m.raw).toContain("Bearer [redacted]");
  });
  it("403 on deploy is not the store-role hint", () => {
    expect(mapWranglerError("deploy", "403 authorization").kind).toBe("unknown");
  });
});
