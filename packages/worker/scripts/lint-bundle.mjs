// Bundle check: `wrangler deploy --dry-run` then fail if the bundle imports any `node:` module or uses a Node global
// (Buffer, process, setImmediate, __dirname, __filename, require). The test runtime has nodejs_compat_v2 (the vitest
// plugin strips no_nodejs_compat_v2), so this script is the only guard for production.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const wrangler = join(dirname(createRequire(import.meta.url).resolve("wrangler/package.json")), "bin", "wrangler.js");
const out = mkdtempSync(join(tmpdir(), "oidc-lint-"));
try {
  const r = spawnSync(process.execPath, [wrangler, "deploy", "--dry-run", "--outdir", out], {
    cwd: pkg, stdio: ["ignore", "inherit", "inherit"], env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false" },
  });
  if (r.status !== 0) process.exit(r.status ?? 1);
  const files = readdirSync(out).filter((f) => f.endsWith(".js"));
  if (files.length === 0) { console.error("lint: no bundle produced"); process.exit(1); }
  for (const f of files) {
    const m = /["']node:[^"']*["']|\b(Buffer|process|setImmediate|__dirname|__filename|require)\b/.exec(readFileSync(join(out, f), "utf8"));
    if (m) { console.error(`lint: bundle ${f} uses Node API ${m[0]}`); process.exit(1); }
  }
  console.log(`lint: ${files.join(", ")} has no node: imports or Node globals`);
} finally {
  rmSync(out, { recursive: true, force: true });
}
