import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isKid } from "./lib/kid.js";
import { generatePrivateJwk } from "./lib/keygen.js";
import { summarize } from "./lib/jsonc.js";
import { buildJwksTable } from "./lib/jwks.js";
import { verifyChecks, verifyPassed } from "./lib/verify.js";
import { validateIssuer } from "./lib/validators.js";
import { fetchJson, fetchJwks } from "./lib/http.js";

const HELP = `workers-oidc-issuer [--worker-dir <path>] [command]

Interactive TUI when run with no command in a terminal.

Commands:
  keys list [--json]      list kids (manual: bindings; auto: served JWKS)
  verify --issuer <url>   check discovery + JWKS of a deployed issuer
  keygen --kid <kid>      print a fresh private JWK for <kid> (stdout only)
  --help
`;

const [major, minor] = process.versions.node.split(".").map(Number) as [number, number];
if (major < 22 || (major === 22 && minor < 18)) {
  process.stderr.write(`workers-oidc-issuer needs Node >= 22.18 (running ${process.versions.node})\n`);
  process.exit(1);
}

type Argv = { _: string[]; flags: Record<string, string | true> };
function parseArgv(args: string[]): Argv {
  const out: Argv = { _: [], flags: {} };
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const next = args[i + 1];
    if (next !== undefined && !next.startsWith("--")) { out.flags[a.slice(2)] = next; i++; } else out.flags[a.slice(2)] = true;
  }
  return out;
}

function fail(msg: string, code = 1): never {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

export function resolveWorkerDir(flag: string | undefined): string {
  if (flag) return resolve(flag);
  const inRepo = fileURLToPath(new URL("../../worker/", import.meta.url));
  return existsSync(resolve(inRepo, "wrangler.jsonc")) ? inRepo : process.cwd();
}

async function keysList(workerDir: string, json: boolean): Promise<void> {
  const file = resolve(workerDir, "wrangler.jsonc");
  if (!existsSync(file)) fail(`no wrangler.jsonc in ${workerDir} (use --worker-dir)`);
  const s = summarize(readFileSync(file, "utf8"));
  if (s.mode === "manual") {
    const r = { mode: "manual", active: s.activeKid ?? null, published: s.kids };
    process.stdout.write(json ? `${JSON.stringify(r)}\n` : `mode: manual\nactive: ${r.active ?? "(none)"}\npublished: ${r.published.join(", ") || "(none)"}\n`);
    return;
  }
  if (!s.issuer || validateIssuer(s.issuer)) fail("auto mode: vars.ISSUER is not a valid https origin");
  const rows = buildJwksTable(await fetchJwks(s.issuer));
  const r = { mode: "auto", keys: rows.map(({ kid, fp, age }) => ({ kid, fp, age })) };
  process.stdout.write(json ? `${JSON.stringify(r)}\n` : ["mode: auto", ...rows.map((k) => `${k.kid}  ${k.fp}  ${k.age}  ${k.role}`)].join("\n") + "\n");
}

async function verify(issuer: string, workerDir: string): Promise<void> {
  const err = validateIssuer(issuer);
  if (err) fail(err, 2);
  const discovery = await fetchJson(`${issuer}/.well-known/openid-configuration`);
  const jwks = await fetchJson(`${issuer}/.well-known/jwks.json`);
  const file = resolve(workerDir, "wrangler.jsonc");
  const cfg = existsSync(file) ? summarize(readFileSync(file, "utf8")) : undefined;
  const checks = verifyChecks({
    issuer, discovery, jwks,
    ...(cfg?.mode === "manual" ? { expectedKids: cfg.kids } : {}),
    ...(cfg?.mode === "manual" && cfg.activeKid ? { activeKid: cfg.activeKid } : {}),
  });
  for (const c of checks) process.stdout.write(`${c.ok ? "PASS" : c.warn ? "WARN" : "FAIL"}  ${c.name}  ${c.detail}\n`);
  if (!verifyPassed(checks)) process.exit(1);
}

async function keygen(kid: string): Promise<void> {
  if (!isKid(kid)) fail("kid must match ^[a-z0-9]{1,32}$", 2);
  process.stdout.write(`${JSON.stringify(await generatePrivateJwk(kid))}\n`);
}

async function main(): Promise<void> {
  const argv = parseArgv(process.argv.slice(2));
  const wd = argv.flags["worker-dir"];
  const workerDir = resolveWorkerDir(typeof wd === "string" ? wd : undefined);
  if (argv.flags["help"] || argv._[0] === "help") { process.stdout.write(HELP); return; }
  const [cmd, sub] = argv._;
  if (cmd === "keys" && sub === "list") return keysList(workerDir, argv.flags["json"] === true);
  if (cmd === "verify") {
    const issuer = argv.flags["issuer"];
    if (typeof issuer !== "string") fail("verify needs --issuer <url>", 2);
    return verify(issuer, workerDir);
  }
  if (cmd === "keygen") {
    const kid = argv.flags["kid"];
    if (typeof kid !== "string") fail("keygen needs --kid <kid>", 2);
    return keygen(kid);
  }
  if (cmd !== undefined) fail(`unknown command: ${argv._.join(" ")}\n\n${HELP}`, 2);
  if (!process.stdin.isTTY || !process.stdout.isTTY) fail("interactive mode needs a TTY; use a --json subcommand", 2);
  const app = await import("./app.js");
  app.run(workerDir);
}

main().catch((e: unknown) => fail(e instanceof Error ? e.message : String(e)));
