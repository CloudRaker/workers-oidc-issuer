import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const bin = fileURLToPath(new URL("../dist/bin.js", import.meta.url));
const worker = fileURLToPath(new URL("../../worker", import.meta.url));

describe("dist/bin.js", () => {
  it("keys list --json prints JSON and exits 0", () => {
    const r = spawnSync(process.execPath, [bin, "keys", "list", "--json", "--worker-dir", worker], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ mode: "manual", active: "k0", published: ["k0"] });
  });
  it("verify rejects a non-https issuer with exit 2 and no network", () => {
    const r = spawnSync(process.execPath, [bin, "verify", "--issuer", "http://x"], { encoding: "utf8" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("https");
  });
  it("json subcommands never load ink: bin.js imports only node:/lib statically, app.js dynamically", () => {
    const specs = (s: string) => [...s.matchAll(/^(?:import|export)[^;]*?from\s+"([^"]+)"/gm)].map((m) => m[1]);
    const src = readFileSync(bin, "utf8");
    for (const s of specs(src)) expect(s, `static import in bin.js: ${s}`).toMatch(/^(node:|\.\/lib\/)/);
    expect(src).toMatch(/import\("\.\/app\.js"\)/);
    const lib = join(dirname(bin), "lib");
    for (const f of readdirSync(lib)) for (const s of specs(readFileSync(join(lib, f), "utf8"))) expect(s, `${f}: ${s}`).toMatch(/^(node:|\.\/|jsonc-parser$)/);
  });
  it("no args with piped stdin exits 2", () => {
    const r = spawnSync(process.execPath, [bin], { encoding: "utf8", input: "" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("interactive mode needs a TTY");
  });
  it("keygen prints a private JWK with the exact member set", () => {
    const r = spawnSync(process.execPath, [bin, "keygen", "--kid", "k20261022abcd"], { encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(Object.keys(JSON.parse(r.stdout) as object).sort()).toEqual(["alg", "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"]);
    expect(spawnSync(process.execPath, [bin, "keygen", "--kid", "BAD"], { encoding: "utf8" }).status).toBe(2);
  });
});
