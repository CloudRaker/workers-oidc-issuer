import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseConfig, setAccountId, summarize, type Summary } from "../lib/jsonc.js";
import { parseCreatedSecret, parseDeployOutput, parseSecretList, parseStoreList, parseWhoami, type Account, type Secret } from "../lib/parsers.js";
import type { Mapped } from "../lib/wrangler-errors.js";
import type { RunOpts, RunResult } from "../lib/wrangler.js";
import type { MenuItem } from "../ui.js";

export class Cancelled extends Error {
  constructor() { super("cancelled"); }
}
export class WranglerError extends Error {
  constructor(public readonly mapped: Mapped) { super(mapped.message); }
}

/** What a screen's async flow can do: prompt the operator, log lines, run wrangler. */
export type Flow = {
  workerDir: string;
  menu(title: string, items: MenuItem[]): Promise<string>;
  text(label: string, o?: { mask?: boolean; validate?: (s: string) => string | null }): Promise<string>;
  confirm(text: string): Promise<boolean>;
  log(line: string): void;
  /** Streams output into the log; throws WranglerError on non-zero exit unless allowFail. */
  wrangler(args: string[], o?: RunOpts & { allowFail?: boolean }): Promise<RunResult>;
};

export const configPath = (workerDir: string): string => resolve(workerDir, "wrangler.jsonc");
export function readConfig(workerDir: string): string {
  const p = configPath(workerDir);
  if (!existsSync(p)) throw new Error(`no wrangler.jsonc in ${workerDir} (use --worker-dir)`);
  return readFileSync(p, "utf8");
}
export const writeConfig = (workerDir: string, text: string): void => writeFileSync(configPath(workerDir), text);
export const readSummary = (workerDir: string): Summary => summarize(readConfig(workerDir));

export async function whoami(f: Flow): Promise<{ email: string | null; accounts: Account[] }> {
  // a non-zero exit (offline, OAuth refresh, wrangler startup) goes through the flow's mapper so the cause is shown
  const r = await f.wrangler(["whoami", "--json"]);
  const w = parseWhoami(r.stdout, r.stderr);
  if (!w.loggedIn) throw new Error("Not logged in. Run `wrangler login` in a terminal, then retry.");
  return w;
}

export async function pickAccount(f: Flow, accounts: Account[]): Promise<string> {
  const id = await f.menu("Pick the Cloudflare account to pin (written as account_id in wrangler.jsonc)", accounts.map((a) => ({ label: a.name, value: a.id, hint: a.id })));
  writeConfig(f.workerDir, setAccountId(readConfig(f.workerDir), id));
  f.log(`pinned account_id ${id}`);
  return id;
}

/** Account id to use: pinned in wrangler.jsonc, the only one, or picked. */
export async function ensureAccount(f: Flow): Promise<{ email: string | null; accountId: string }> {
  const w = await whoami(f);
  const pinned = parseConfig(readConfig(f.workerDir)).account_id;
  if (pinned) return { email: w.email, accountId: pinned };
  if (w.accounts.length === 0) throw new Error("This login reaches no account.");
  if (w.accounts.length === 1) return { email: w.email, accountId: (w.accounts[0] as Account).id };
  return { email: w.email, accountId: await pickAccount(f, w.accounts) };
}

/** The account's Secrets Store id; creates `default` when there is none. */
export async function ensureStore(f: Flow): Promise<string> {
  const list = async () => parseStoreList((await f.wrangler(["secrets-store", "store", "list", "--remote"], { allowFail: true })).stdout);
  let stores = await list();
  if (stores.length === 0) {
    f.log("no Secrets Store yet; creating `default`");
    await f.wrangler(["secrets-store", "store", "create", "default", "--remote"]);
    stores = await list();
  }
  const s = stores.find((x) => x.name === "default") ?? stores[0];
  if (!s) throw new Error("secrets-store store list returned no store after create");
  return s.id;
}

/** Value goes to wrangler's stdin as one line; never argv. */
export async function createSecret(f: Flow, storeId: string, name: string, value: string): Promise<string | null> {
  const r = await f.wrangler(["secrets-store", "secret", "create", storeId, "--name", name, "--scopes", "workers", "--remote"], { stdin: value });
  return parseCreatedSecret(r.stdout);
}

/** `secret list` exits 1 on an empty store; allowFail + parser yield []. wrangler pages 10 by default; 100 is the account limit, so one page holds the store. */
export async function listSecrets(f: Flow, storeId: string): Promise<Secret[]> {
  return parseSecretList((await f.wrangler(["secrets-store", "secret", "list", storeId, "--remote", "--per-page", "100"], { allowFail: true })).stdout);
}

/** Names are unique per store: creates, or updates the value in place (wrangler's non-interactive confirm falls back to yes, then reads stdin). */
export async function upsertSecret(f: Flow, storeId: string, name: string, value: string, existing: Secret[]): Promise<void> {
  const cur = existing.find((s) => s.name === name);
  if (!cur) { await createSecret(f, storeId, name, value); return; }
  f.log(`${name} already exists; updating it in place (same secret id; bindings unchanged)`);
  await f.wrangler(["secrets-store", "secret", "update", storeId, "--secret-id", cur.id, "--remote"], { stdin: value });
}

/** `wrangler deploy`; returns deploy targets (workers.dev URL and routes). */
export async function deploy(f: Flow): Promise<string[]> {
  const dir = mkdtempSync(join(tmpdir(), "oidc-deploy-"));
  const out = join(dir, "deploy.ndjson");
  try {
    const r = await f.wrangler(["deploy"], { env: { WRANGLER_OUTPUT_FILE_PATH: out } });
    const targets = parseDeployOutput(existsSync(out) ? readFileSync(out, "utf8") : null, r.stdout);
    f.log(targets.length ? `deployed: ${targets.join(", ")}` : "deployed (no targets reported)");
    return targets;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function issuerFromTargets(targets: string[]): string | null {
  const t = targets.find((x) => /\.workers\.dev\b/.test(x));
  return t ? `https://${t.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}` : null;
}

/** Origin to poll: ISSUER when it is a deploy target, else the live workers.dev target. The Worker routes on pathname only and builds issuer/jwks_uri from ISSUER, so both hosts serve the same JWKS and both trigger the lazy tick. */
export function probeOrigin(f: Flow, issuer: string, targets: string[]): string {
  const host = new URL(issuer).host;
  const norm = (t: string) => t.replace(/^https?:\/\//, "").replace(/\/\*?$/, "");
  if (targets.some((t) => norm(t) === host)) return issuer;
  const wd = issuerFromTargets(targets);
  if (wd) f.log(`ISSUER ${host} is not a deploy target; polling ${wd} instead. Add a custom_domain route for ${host} before Verify can pass.`);
  return wd ?? issuer;
}

export const PENDING_ISSUER = "https://PENDING";
