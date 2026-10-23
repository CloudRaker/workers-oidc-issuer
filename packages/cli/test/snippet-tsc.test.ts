import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { snippetCode, snippetConfig } from "../src/lib/snippet.js";

const req = createRequire(import.meta.url);
const workerDir = fileURLToPath(new URL("../../worker/", import.meta.url));
const workersTypes = req.resolve("@cloudflare/workers-types/experimental/index.d.ts", { paths: [workerDir] });
const tsc = join(req.resolve("typescript/package.json"), "..", "bin", "tsc");

describe("consumer snippet", () => {
  it("typechecks against @cloudflare/workers-types", () => {
    const dir = mkdtempSync(join(tmpdir(), "oidc-snippet-"));
    try {
      const i = { worker: "billing-api", issuerName: "oidc-issuer", sub: "billing-api", aud: ["sts.amazonaws.com"] };
      writeFileSync(join(dir, "index.ts"), snippetCode(i));
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({
        compilerOptions: { strict: true, noEmit: true, target: "ES2022", module: "ESNext", moduleResolution: "Bundler", lib: ["ES2022"], types: [], skipLibCheck: true },
        files: ["index.ts", workersTypes],
      }));
      const r = spawnSync(process.execPath, [tsc, "-p", dir], { encoding: "utf8" });
      expect(r.status, r.stdout + r.stderr).toBe(0);
      expect(JSON.parse(snippetConfig(i))).toMatchObject({ services: [{ binding: "OIDC", entrypoint: "Issuer", props: { sub: "billing-api", aud: ["sts.amazonaws.com"] } }] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
