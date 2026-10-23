import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunOpts, RunResult } from "../src/lib/wrangler.js";

/* ---------- wrangler double ---------- */

const ISSUER = "https://oidc-issuer.acme.workers.dev";
const STORE = "7b1e2f3a4c5d6e7f8091a2b3c4d5e6f7";
const ACC = (n: number) => ({ name: `Acme ${n}`, id: `${n}`.repeat(32) });
const fake = {
  accounts: [ACC(1)],
  calls: [] as string[][],
  secrets: {} as Record<string, string>, // name -> value handed over stdin (lengths asserted, never printed)
  deployFail: null as string | null,
  deployFailOnce: null as string | null, // first deploy fails, the retry succeeds: covers the multi-account picker path in flow.tsx
  deployStdout: null as string | null, // stdout printed before a failing deploy (bindings table)
  secretList: [] as { name: string; id: string }[],
  updated: {} as Record<string, string>, // secret id -> value handed to `secret update` over stdin
  whoami: null as RunResult | null,
};
const table = (rows: { name: string; id: string }[], head = ["Name", "ID"]) =>
  [`│ ${head.join(" │ ")} │`, ...rows.map((r) => `│ ${r.name} │ ${r.id} │`)].join("\n");

async function fakeWrangler(args: string[], o: RunOpts = {}): Promise<RunResult> {
  fake.calls.push(args);
  const say = (s: string, stream: "stdout" | "stderr" = "stdout") => { for (const l of s.split("\n")) if (l) o.onOutput?.(redact(l), stream); return s; }; // mirrors spawnNode's tap
  const cmd = args.slice(0, 3).join(" ");
  if (cmd.startsWith("whoami")) {
    if (fake.whoami) { say(fake.whoami.stdout); say(fake.whoami.stderr, "stderr"); return fake.whoami; }
    return { code: 0, stdout: say(JSON.stringify({ loggedIn: true, email: "op@example.com", accounts: fake.accounts })), stderr: "" };
  }
  if (cmd === "secrets-store store list") return { code: 0, stdout: say(table([{ name: "default", id: STORE }])), stderr: "" };
  if (cmd === "secrets-store secret create") {
    const name = args[args.indexOf("--name") + 1] as string;
    fake.secrets[name] = o.stdin ?? "";
    return { code: 0, stdout: say(`Created secret! (ID: 11111111-2222-3333-4444-${name.length.toString().padStart(12, "0")})`), stderr: "" };
  }
  if (cmd === "secrets-store secret list") {
    expect(args.slice(-2)).toEqual(["--per-page", "100"]); // wrangler defaults to 10; the store is shared with every other app
    if (fake.secretList.length === 0) return { code: 1, stdout: "", stderr: say("✘ [ERROR] List request returned no secrets.", "stderr") };
    return { code: 0, stdout: say(table(fake.secretList)), stderr: "" };
  }
  if (cmd === "secrets-store secret update") { fake.updated[args[args.indexOf("--secret-id") + 1] as string] = o.stdin ?? ""; return { code: 0, stdout: say("Updated"), stderr: "" }; }
  if (cmd === "secrets-store secret delete") return { code: 0, stdout: say("Deleted"), stderr: "" };
  if (cmd === "deploy") {
    if (fake.deployFailOnce) { const m = fake.deployFailOnce; fake.deployFailOnce = null; return { code: 1, stdout: "", stderr: say(`✘ [ERROR] ${m}`, "stderr") }; }
    if (fake.deployFail) return { code: 1, stdout: say(fake.deployStdout ?? ""), stderr: say(`✘ [ERROR] ${fake.deployFail}`, "stderr") };
    return { code: 0, stdout: say(`Uploaded oidc-issuer\nDeployed oidc-issuer triggers (1.0 sec)\n  ${ISSUER.replace("https://", "")}\nCurrent Version ID: abc`), stderr: "" };
  }
  return { code: 1, stdout: "", stderr: say(`unknown fake command ${cmd}`, "stderr") };
}
// the real redact stays: the error panel must hide secrets even when they arrive in raw stderr
vi.mock("../src/lib/wrangler.js", async (orig) => ({
  ...(await orig<typeof import("../src/lib/wrangler.js")>()),
  runWrangler: (_d: string, a: string[], o?: RunOpts) => fakeWrangler(a, o),
}));

/* ---------- fetch double ---------- */

const key = (kid: string) => ({ kty: "RSA", n: `n-${kid}`, e: "AQAB", kid, alg: "RS256", use: "sig" });
const jwksState = { kids: ["k1700000000abcd"], fail: false };
vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
  const url = String(input);
  if (url === `${ISSUER}/.well-known/openid-configuration`) return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json`, id_token_signing_alg_values_supported: ["RS256"] });
  if (url === `${ISSUER}/.well-known/jwks.json`) return jwksState.fail ? new Response("", { status: 500 }) : Response.json({ keys: jwksState.kids.map(key) });
  // store list, keyset search and the PATCH probe all succeed with one permissive answer
  if (url.startsWith("https://api.cloudflare.com/client/v4/accounts/")) return Response.json({ result: [{ id: STORE, name: "default" }, { id: "ks-id", name: "OIDC_KEYSET" }] });
  return new Response("", { status: 404 });
}));

/* ---------- helpers ---------- */

const { redact } = await import("../src/lib/wrangler.js");
const { isIso8601 } = await import("../src/lib/validators.js");
const { App } = await import("../src/app.js");
const { Keys } = await import("../src/screens/keys.js");
const { Setup } = await import("../src/screens/setup.js");
const { Verify } = await import("../src/screens/verify.js");
const { Snippet } = await import("../src/screens/snippet.js");
const { Deploy } = await import("../src/screens/deploy.js");
const { NavContext } = await import("../src/ui.js");

const fixture = readFileSync(fileURLToPath(new URL("./fixtures/wrangler.jsonc", import.meta.url)), "utf8");
const ESC = "\u001B";
const DOWN = "\u001B[B";
const PAGE_UP = "\u001B[5~";
const ENTER = "\r";
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));
async function until(frame: () => string | undefined, re: RegExp, ms = 8000): Promise<string> {
  const end = Date.now() + ms;
  for (;;) {
    const f = frame() ?? "";
    if (re.test(f)) return f;
    if (Date.now() > end) throw new Error(`timeout waiting for ${re}; last frame:\n${f}`);
    await tick(20);
  }
}
async function keys(stdin: { write: (s: string) => void }, ...seq: string[]): Promise<void> {
  await tick(20); // a frame can be visible before its useInput effect is attached; a key sent in that window is lost
  for (const k of seq) { stdin.write(k); await tick(40); }
}

let dir: string;
const cfg = () => readFileSync(join(dir, "wrangler.jsonc"), "utf8");
const manualCfg = (kids: string[], active: string) =>
  fixture
    .replace('"ACTIVE_KID": "k0"', `"ACTIVE_KID": "${active}"`)
    .replace('"ISSUER": "https://PENDING"', `"ISSUER": "${ISSUER}"`)
    .replace(/\{ "binding": "OIDC_KEY_k0"[^\n]*\}/, kids.map((k) => `{ "binding": "OIDC_KEY_${k}", "store_id": "${STORE}", "secret_name": "OIDC_KEY_${k}" }`).join(",\n    "));
const autoCfg = () =>
  fixture
    .replace('"ROTATION": "manual"', '"ROTATION": "auto"')
    .replace('"ISSUER": "https://PENDING"', `"ISSUER": "${ISSUER}"`)
    .replace('"ACTIVE_KID": "k0",', '"SECRETS_STORE_ID": "' + STORE + '", "ROTATION_INTERVAL_HOURS": "720", "ROTATION_GRACE_HOURS": "24", "ROTATE_NONCE": "", "REVOKE_BEFORE": "", "RETIRE_KIDS": "[]",')
    .replace(/\{ "binding": "OIDC_KEY_k0"[^\n]*\}/, `{ "binding": "OIDC_KEYSET", "store_id": "${STORE}", "secret_name": "OIDC_KEYSET" }`);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oidc-cli-"));
  writeFileSync(join(dir, "wrangler.jsonc"), fixture);
  fake.calls = []; fake.secrets = {}; fake.accounts = [ACC(1)]; fake.deployFail = null; fake.deployFailOnce = null; fake.deployStdout = null; fake.secretList = []; fake.updated = {}; fake.whoami = null;
  jwksState.kids = ["k1700000000abcd"]; jwksState.fail = false;
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const nav = { back: vi.fn(), quit: vi.fn() };
const withNav = (el: React.ReactElement) => <NavContext.Provider value={nav}>{el}</NavContext.Provider>;

/* ---------- tests ---------- */

describe("Home", () => {
  it("renders auth, config summary and the menu; Esc on Home quits", async () => {
    const r = render(<App workerDir={dir} />);
    const f = await until(r.lastFrame, /logged in as op@example.com/);
    expect(f).toContain("mode manual");
    expect(f).toContain("active k0");
    expect(f).toContain("> Setup");
    expect(f).toContain("Change account");
    r.unmount();
  });
  it("navigates to Deploy, shows the URL, Esc returns Home", async () => {
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /> Setup/);
    await keys(r.stdin, DOWN, DOWN, ENTER);
    const f = await until(r.lastFrame, /URL: https:\/\/oidc-issuer\.acme\.workers\.dev/);
    expect(f).toContain("$ wrangler deploy");
    expect(f).toContain("Deployed oidc-issuer triggers");
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Setup/);
    r.unmount();
  });
  it("whoami failure: Home shows the stderr cause; flows show the mapped error with raw stderr", async () => {
    fake.whoami = { code: 1, stdout: "", stderr: "✘ [ERROR] fetch failed\n" };
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /auth: ✘ \[ERROR\] fetch failed/);
    await keys(r.stdin, DOWN, DOWN, DOWN, DOWN, DOWN, ENTER);
    const f = await until(r.lastFrame, /wrangler whoami --json failed/);
    expect(f).toContain("fetch failed");
    r.unmount();
    fake.whoami = { code: 1, stdout: '{"loggedIn":false}\n', stderr: "" };
    const r2 = render(<App workerDir={dir} />);
    await until(r2.lastFrame, /not logged in/);
    await keys(r2.stdin, DOWN, DOWN, DOWN, DOWN, DOWN, ENTER);
    await until(r2.lastFrame, /Not logged in\. Run `wrangler login`/);
    r2.unmount();
  });
  it("Change account: picker writes account_id", async () => {
    fake.accounts = [ACC(1), ACC(2)];
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /several accounts, none pinned/);
    await keys(r.stdin, DOWN, DOWN, DOWN, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /Pick the Cloudflare account/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /pinned account_id 2{32}/);
    expect(cfg()).toContain(`"account_id": "${"2".repeat(32)}"`);
    expect(cfg()).toContain("no_nodejs_compat"); // comments and flags survive
    expect(cfg()).toContain("// no_nodejs_compat*");
    r.unmount();
  });
});

describe("Setup", () => {
  it("manual branch: key over stdin, wrangler.jsonc rewritten, deploy twice, lands on Verify", async () => {
    fake.accounts = [ACC(1), ACC(2)];
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /> Setup/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Pick the Cloudflare account/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Key management mode/);
    expect(r.lastFrame()).toContain("no API token needed");
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /^\s*(PASS|FAIL)$/m, 15000); // the fetch stub cannot serve the freshly generated kid
    expect(f).toMatch(/PASS\s+discovery\.issuer/);
    const text = cfg();
    expect(text).toContain('"ROTATION": "manual"');
    expect(text).toContain(`"ISSUER": "${ISSUER}"`);
    expect(text).not.toContain("REPLACE_ME");
    expect(text).toContain(`"account_id": "${"1".repeat(32)}"`);
    const kid = /"ACTIVE_KID": "(k\d{8}[0-9a-f]{4})"/.exec(text)?.[1] as string;
    expect(kid).toBeTruthy();
    expect(text).toMatch(new RegExp(`"binding":\\s*"OIDC_KEY_${kid}",\\s*"store_id":\\s*"${STORE}"`));
    const jwk = JSON.parse(fake.secrets[`OIDC_KEY_${kid}`] as string) as Record<string, string>;
    expect(Object.keys(jwk).sort()).toEqual(["alg", "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"]);
    expect(jwk["kid"]).toBe(kid);
    expect(fake.calls.filter((c) => c[0] === "deploy")).toHaveLength(2);
    expect(fake.calls.find((c) => c[2] === "create")).toEqual(["secrets-store", "secret", "create", STORE, "--name", `OIDC_KEY_${kid}`, "--scopes", "workers", "--remote"]);
    r.unmount();
  });
  it("auto branch: masked token, validated, two secrets, auto config, waits for a key", async () => {
    jwksState.kids = [];
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /> Setup/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /ISSUER origin/);
    r.stdin.write("https://bad/x"); await tick(40);
    await keys(r.stdin, ENTER);
    expect(r.lastFrame()).toContain("origin only");
    for (let i = 0; i < 13; i++) r.stdin.write("\u007F");
    await tick(40);
    r.stdin.write(ISSUER); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Paste the API token/);
    const token = "tok_" + "s3cr3t".repeat(6);
    r.stdin.write(token); await tick(40);
    expect(r.lastFrame()).not.toContain("s3cr3t");
    expect(r.lastFrame()).toContain("*".repeat(token.length));
    setTimeout(() => { jwksState.kids = ["k1700000001beef"]; }, 300);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /^\s*PASS$/m, 15000);
    expect(f).toMatch(/PASS\s+jwks\.nonEmpty/);
    expect(fake.secrets["OIDC_CF_API_TOKEN"]).toBe(token);
    expect(fake.secrets["OIDC_KEYSET"]).toBe('{"v":1,"version":0,"active":"","keys":[]}');
    const text = cfg();
    expect(text).toContain('"ROTATION": "auto"');
    expect(text).toContain(`"CF_ACCOUNT_ID": "${"1".repeat(32)}"`);
    expect(text).toContain(`"SECRETS_STORE_ID": "${STORE}"`);
    expect(text).toContain('"binding": "CF_API_TOKEN"');
    expect(text).toMatch(/"class_name":\s*"KeyRing"/);
    expect(text).toMatch(/"crons":\s*\["17 \* \* \* \*"\]/);
    expect(text).not.toContain("ACTIVE_KID");
    expect(text).not.toContain("OIDC_KEY_k0");
    expect(fake.calls.filter((c) => c[0] === "deploy")).toHaveLength(1);
    expect(fake.calls.map((c) => c.join(" ")).join("\n")).not.toContain("s3cr3t");
    r.unmount();
  });
  it("auto branch re-run: token updated in place by id, existing OIDC_KEYSET kept, nothing re-created", async () => {
    fake.secretList = [{ name: "OIDC_CF_API_TOKEN", id: "tok-id" }, { name: "OIDC_KEYSET", id: "ks-id" }];
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /> Setup/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Paste the API token/);
    const token = "tok_" + "n3wt0k".repeat(6);
    r.stdin.write(token); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /^\s*(PASS|FAIL)$/m, 15000);
    expect(fake.calls).toContainEqual(["secrets-store", "secret", "update", STORE, "--secret-id", "tok-id", "--remote"]);
    expect(fake.updated["tok-id"]).toBe(token);
    expect(fake.calls.filter((c) => c[2] === "create")).toEqual([]);
    expect(fake.secrets).toEqual({});
    expect(cfg()).toContain('"ROTATION": "auto"');
    r.unmount();
  });
  it("manual re-run on a live manual issuer keeps the bindings and ACTIVE_KID; no new key", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa"], "k20260101aaaa"));
    fake.secretList = [{ name: "OIDC_KEY_k20260101aaaa", id: "aaaa-id" }];
    const r = render(withNav(<Setup workerDir={dir} onDeployed={() => {}} onDone={() => {}} />));
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /setup complete/, 15000);
    await keys(r.stdin, PAGE_UP, PAGE_UP); // the output box scrolled past the early lines
    await until(r.lastFrame, /keeping existing OIDC_KEY_\* bindings \(k20260101aaaa\)/);
    const text = cfg();
    expect(text).toContain('"ACTIVE_KID": "k20260101aaaa"');
    expect(text.match(/"binding": "OIDC_KEY_/g)).toHaveLength(1);
    expect(fake.calls.filter((c) => c[2] === "create")).toEqual([]);
    expect(fake.calls.filter((c) => c[2] === "delete")).toEqual([]);
    r.unmount();
  });
  it("switching auto -> manual deletes the stored token and keyset after the deploy and says to revoke the token", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    fake.secretList = [{ name: "OIDC_CF_API_TOKEN", id: "tok-id" }, { name: "OIDC_KEYSET", id: "ks-id" }];
    const r = render(withNav(<Setup workerDir={dir} onDeployed={() => {}} onDone={() => {}} />));
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /setup complete/, 15000);
    expect(f).toContain("profile/api-tokens");
    const del = (id: string) => ["secrets-store", "secret", "delete", STORE, "--secret-id", id, "--remote"];
    expect(fake.calls).toContainEqual(del("tok-id"));
    expect(fake.calls).toContainEqual(del("ks-id"));
    const lastDeploy = fake.calls.map((c) => c[0]).lastIndexOf("deploy");
    expect(fake.calls.findIndex((c) => c[5] === "tok-id")).toBeGreaterThan(lastDeploy);
    expect(fake.calls.findIndex((c) => c[5] === "ks-id")).toBeGreaterThan(lastDeploy);
    expect(cfg()).not.toContain("CF_API_TOKEN");
    expect(cfg()).toContain('"ROTATION": "manual"');
    r.unmount();
  });
  it("manual on a config that was never auto leaves OIDC_KEYSET / OIDC_CF_API_TOKEN in the store (another issuer may own them)", async () => {
    fake.secretList = [{ name: "OIDC_CF_API_TOKEN", id: "tok-id" }, { name: "OIDC_KEYSET", id: "ks-id" }];
    const r = render(withNav(<Setup workerDir={dir} onDeployed={() => {}} onDone={() => {}} />));
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /ISSUER/);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /setup complete/, 15000);
    expect(f).not.toContain("profile/api-tokens");
    expect(f).toContain("this config was not in auto mode");
    expect(fake.calls.filter((c) => c[2] === "delete")).toEqual([]);
    expect(cfg()).toContain('"ROTATION": "manual"');
    r.unmount();
  });
  it("re-run offers to keep a valid ISSUER and never writes the PENDING placeholder, so a failed deploy leaves it intact", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    fake.secretList = [{ name: "OIDC_CF_API_TOKEN", id: "tok-id" }, { name: "OIDC_KEYSET", id: "ks-id" }];
    fake.deployFail = "transient API error";
    const r = render(withNav(<Setup workerDir={dir} onDeployed={() => {}} onDone={() => {}} />));
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, DOWN, ENTER);
    const m = await until(r.lastFrame, /ISSUER/);
    expect(m).toContain(`> keep ${ISSUER}`);
    await keys(r.stdin, DOWN, ENTER); // "workers.dev URL from the first deploy" on a live issuer
    await until(r.lastFrame, /Paste the API token/);
    r.stdin.write("tok_" + "n3wt0k".repeat(6)); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /wrangler deploy failed/, 15000);
    expect(cfg()).toContain(`"ISSUER": "${ISSUER}"`);
    expect(cfg()).not.toContain("PENDING");
    r.unmount();
  });
  it("Esc at a prompt cancels; Esc again goes Home", async () => {
    const r = render(<App workerDir={dir} />);
    await until(r.lastFrame, /> Setup/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /Key management mode/);
    await keys(r.stdin, ESC);
    const f = await until(r.lastFrame, /esc back, q quit/);
    expect(f).not.toContain("Key management mode");
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Setup/);
    expect(cfg()).toBe(fixture);
    r.unmount();
  });
  it("multi-account stderr opens the picker, pins account_id and retries", async () => {
    fake.accounts = [ACC(1), ACC(2)];
    fake.deployFailOnce = "More than one account available but unable to select one in non-interactive mode.";
    const r = render(withNav(<Deploy workerDir={dir} onDeployed={() => {}} />));
    await until(r.lastFrame, /Pick the Cloudflare account/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /URL: https:\/\/oidc-issuer\.acme\.workers\.dev/);
    expect(cfg()).toContain(`"account_id": "${"2".repeat(32)}"`);
    expect(fake.calls.filter((c) => c[0] === "deploy")).toHaveLength(2);
    r.unmount();
  });
  it("keeps the stderr error in the ErrorView tail when deploy printed a long stdout first", async () => {
    fake.deployStdout = Array.from({ length: 20 }, (_, i) => `| var${i} |`).join("\n");
    fake.deployFail = "A request to the Cloudflare API failed [code: 10021]";
    const r = render(withNav(<Deploy workerDir={dir} onDeployed={() => {}} />));
    const f = await until(r.lastFrame, /wrangler deploy failed/);
    expect(f.slice(f.indexOf("wrangler deploy failed"))).toContain("✘ [ERROR] A request to the Cloudflare API failed");
    r.unmount();
  });
  it("shows the mapped error plus raw stderr when deploy fails", async () => {
    fake.deployFail = "Please register a workers.dev subdomain before deploying";
    const r = render(withNav(<Deploy workerDir={dir} onDeployed={() => {}} />));
    const f = await until(r.lastFrame, /no workers\.dev subdomain yet/);
    expect(f).toContain("workers/onboarding");
    expect(f).toContain("✘ [ERROR] Please register a workers.dev subdomain");
    r.unmount();
  });
  it("redacts tokens and private JWK members in the error panel", async () => {
    fake.deployFail = `Authorization: Bearer ${"A".repeat(48)} {"d":"${"B".repeat(50)}"}`;
    const r = render(withNav(<Deploy workerDir={dir} onDeployed={() => {}} />));
    const f = await until(r.lastFrame, /wrangler deploy failed/);
    expect(f).not.toContain("A".repeat(48));
    expect(f).not.toContain("B".repeat(50));
    expect(f).toContain("Bearer [redacted]");
    expect(f).toContain('"d":"[redacted]"');
    r.unmount();
  });
});

describe("Keys manual", () => {
  it("lists roles; Add generates, uploads, binds and deploys", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa"], "k20260101aaaa"));
    const r = render(withNav(<Keys workerDir={dir} />));
    const f0 = await until(r.lastFrame, /> Add key/);
    expect(f0).toMatch(/k20260101aaaa\s+ACTIVE/);
    expect(f0).toContain("Add -> wait 1h -> Promote -> wait 1h -> Remove");
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /is published; wait >= 1h/, 15000);
    const kid = /generating RSA-2048 key (k\w+)/.exec(f)?.[1] as string;
    expect(cfg()).toContain(`"binding": "OIDC_KEY_${kid}"`);
    expect(JSON.parse(fake.secrets[`OIDC_KEY_${kid}`] as string)).toHaveProperty("d");
    expect(f).not.toContain('"d":"'); // nothing private rendered
    await keys(r.stdin, ESC);
    const list = await until(r.lastFrame, /> Add key/);
    expect(list).toMatch(new RegExp(`${kid}\\s+PUBLISHED`));
    r.unmount();
  });
  it("Promote sets ACTIVE_KID; Remove refuses ACTIVE, deletes the secret by id", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa", "k20260202bbbb"], "k20260101aaaa"));
    fake.secretList = [{ name: "OIDC_KEY_k20260101aaaa", id: "aaaaaaaa-0000-0000-0000-000000000000" }];
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Add key/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /Promote which kid/);
    expect(r.lastFrame()).not.toContain("> k20260101aaaa");
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /k20260202bbbb is ACTIVE/);
    expect(cfg()).toContain('"ACTIVE_KID": "k20260202bbbb"');
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /k20260202bbbb\s+ACTIVE/);
    await keys(r.stdin, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /Remove which kid/);
    expect(r.lastFrame()).toContain("k20260101aaaa");
    expect(r.lastFrame()).not.toContain("> k20260202bbbb");
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /\[y\/N\]/);
    await keys(r.stdin, "y");
    await until(r.lastFrame, /removed from the Worker and the store/);
    expect(cfg()).not.toContain("OIDC_KEY_k20260101aaaa");
    expect(fake.calls).toContainEqual(["secrets-store", "secret", "list", STORE, "--remote", "--per-page", "100"]); // wrangler defaults to 10 per page; 100 is the account limit
    expect(fake.calls).toContainEqual(["secrets-store", "secret", "delete", STORE, "--secret-id", "aaaaaaaa-0000-0000-0000-000000000000", "--remote"]);
    r.unmount();
  });
  it("Remove fails loudly when the secret is not in the store, and deletes nothing", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa", "k20260202bbbb"], "k20260202bbbb"));
    fake.secretList = [];
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Add key/);
    await keys(r.stdin, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /Remove which kid/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /\[y\/N\]/);
    await keys(r.stdin, "y");
    const f = await until(r.lastFrame, /no secret named OIDC_KEY_k20260101aaaa/);
    expect(f).toContain("--per-page 100");
    expect(fake.calls.some((c) => c[2] === "delete")).toBe(false);
    r.unmount();
  });
  it("Remove restores the binding when deploy fails, so the secret is not orphaned", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa", "k20260202bbbb"], "k20260202bbbb"));
    fake.deployFail = "transient API error";
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Add key/);
    await keys(r.stdin, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /Remove which kid/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /\[y\/N\]/);
    await keys(r.stdin, "y");
    await until(r.lastFrame, /wrangler deploy failed/);
    expect(cfg()).toContain('"binding": "OIDC_KEY_k20260101aaaa"');
    expect(fake.calls.some((c) => c[2] === "delete")).toBe(false);
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /k20260101aaaa\s+PUBLISHED/);
    r.unmount();
  });
  it("Promote restores ACTIVE_KID when deploy fails, so the file never claims a kid the Worker does not sign with", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k20260101aaaa", "k20260202bbbb"], "k20260101aaaa"));
    fake.deployFail = "transient API error";
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Add key/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /Promote which kid/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /wrangler deploy failed/);
    expect(cfg()).toContain('"ACTIVE_KID": "k20260101aaaa"');
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /k20260101aaaa\s+ACTIVE/);
    r.unmount();
  });
});

describe("Keys auto", () => {
  it("table from JWKS; Rotate now sets ROTATE_NONCE, deploys and re-fetches", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    const r = render(withNav(<Keys workerDir={dir} />));
    const f0 = await until(r.lastFrame, /> Rotate now/);
    expect(f0).toMatch(/k1700000000abcd\s+\S+\s+\d+d\s+active/);
    jwksState.kids = ["k1700000000abcd", "k1700000002cafe"];
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /k1700000002cafe\s+\S+\s+\d+d\s+next/, 10000);
    expect(f).toContain("$ wrangler deploy");
    expect(cfg()).toMatch(/"ROTATE_NONCE": "[0-9a-f]{8}"/);
    r.unmount();
  });
  it("Rotate now refuses while a `next` key is published: no deploy, no ROTATE_NONCE", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    jwksState.kids = ["k1700000000abcd", "k1700000002cafe"];
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /already published/);
    expect(f).not.toContain("$ wrangler deploy");
    expect(fake.calls.filter((c) => c[0] === "deploy")).toHaveLength(0);
    expect(cfg()).toContain('"ROTATE_NONCE": ""');
    r.unmount();
  });
  it("Emergency revoke (y, y) writes an ISO REVOKE_BEFORE, deploys once and shows the new key", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    jwksState.kids = ["k1700000000abcd"];
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /EMERGENCY REVOKE/);
    await keys(r.stdin, "y");
    await until(r.lastFrame, /In-flight tokens will fail/);
    jwksState.kids = ["k1700000009feed"]; // the revoke took effect on the issuer
    await keys(r.stdin, "y");
    const f = await until(r.lastFrame, /k1700000009feed\s+\S+\s+\d+d\s+active/, 10000);
    expect(f).toContain("$ wrangler deploy");
    expect(fake.calls.filter((c) => c[0] === "deploy")).toHaveLength(1);
    const m = /"REVOKE_BEFORE": "([^"]+)"/.exec(cfg());
    expect(m).not.toBeNull();
    expect(isIso8601(m![1]!)).toBe(true); // same regex family as packages/worker/src/config.ts
    expect(Math.abs(Date.parse(m![1]!) - Date.now())).toBeLessThan(60_000);
    r.unmount();
  });
  it("Emergency revoke needs two confirms; Retire picks a non-active kid; Edit schedule validates", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    jwksState.kids = ["k1700000000abcd", "k1700000002cafe"];
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /EMERGENCY REVOKE/);
    await keys(r.stdin, "y");
    await until(r.lastFrame, /In-flight tokens will fail/);
    await keys(r.stdin, "n");
    await until(r.lastFrame, /esc back, q quit/);
    expect(cfg()).toContain('"REVOKE_BEFORE": ""');
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /Retire which key/);
    expect(r.lastFrame()).not.toContain("> k1700000000abcd");
    jwksState.kids = ["k1700000000abcd"];
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /RETIRE_KIDS is left/, 10000);
    expect(cfg()).toContain('"RETIRE_KIDS": "[\\"k1700000002cafe\\"]"');
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, DOWN, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /ROTATION_INTERVAL_HOURS/);
    r.stdin.write("12"); await tick(40);
    await keys(r.stdin, ENTER);
    expect(r.lastFrame()).toContain("integer in [24, 8760]");
    r.stdin.write("0"); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /ROTATION_GRACE_HOURS/);
    r.stdin.write("100"); await tick(40);
    await keys(r.stdin, ENTER);
    expect(r.lastFrame()).toContain("< interval/2");
    r.stdin.write("\u007F\u007F\u007F48"); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /esc back, q quit/);
    expect(cfg()).toContain('"ROTATION_INTERVAL_HOURS": "120"');
    expect(cfg()).toContain('"ROTATION_GRACE_HOURS": "48"');
    r.unmount();
  });
  it("Edit schedule and Emergency revoke run without a JWKS; Rotate still refuses", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), autoCfg());
    jwksState.fail = true;
    const r = render(withNav(<Keys workerDir={dir} />));
    await until(r.lastFrame, /HTTP 500/);
    await keys(r.stdin, DOWN, DOWN, DOWN, ENTER);
    await until(r.lastFrame, /ROTATION_INTERVAL_HOURS/);
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /esc back, q quit/);
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, DOWN, ENTER);
    await until(r.lastFrame, /EMERGENCY REVOKE/);
    await keys(r.stdin, "n");
    await until(r.lastFrame, /esc back, q quit/);
    await keys(r.stdin, ESC);
    await until(r.lastFrame, /> Rotate now/);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /JWKS not loaded/);
    r.unmount();
  });
});

describe("Verify + Snippet", () => {
  it("Verify prints PASS/FAIL per check with manual expectations", async () => {
    writeFileSync(join(dir, "wrangler.jsonc"), manualCfg(["k1700000000abcd", "kmissing"], "k1700000000abcd"));
    const r = render(withNav(<Verify workerDir={dir} targets={["oidc-issuer.acme.workers.dev"]} />));
    const f = await until(r.lastFrame, /^\s*FAIL$/m);
    expect(f).toMatch(/PASS\s+discovery\.jwks_uri/);
    expect(f).toMatch(/FAIL\s+jwks\.bindings\s+missing kmissing/);
    expect(f).toMatch(/PASS\s+deploy\.target/);
    await keys(r.stdin, ESC);
    expect(nav.back).toHaveBeenCalled();
    r.unmount();
  });
  it("Snippet asks name, sub, aud and prints config + typed code", async () => {
    const r = render(withNav(<Snippet workerDir={dir} />));
    await until(r.lastFrame, /Consumer Worker name/);
    r.stdin.write("Bad Name"); await tick(40);
    await keys(r.stdin, ENTER);
    expect(r.lastFrame()).toContain("lowercase letters");
    for (let i = 0; i < 8; i++) r.stdin.write("\u007F");
    r.stdin.write("billing-api"); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /^sub /m);
    r.stdin.write("billing-api"); await tick(40);
    await keys(r.stdin, ENTER);
    await until(r.lastFrame, /aud allow-list/);
    r.stdin.write("sts.amazonaws.com, api://AzureADTokenExchange"); await tick(40);
    await keys(r.stdin, ENTER);
    const f = await until(r.lastFrame, /satisfies ExportedHandler<Env>/);
    expect(f).toContain('"entrypoint": "Issuer"');
    expect(f).toContain('"aud": [');
    expect(f).toContain("OIDC: Service<IssuerApi>");
    expect(f).toContain("Rpc.WorkerEntrypointBranded");
    r.unmount();
  });
});
