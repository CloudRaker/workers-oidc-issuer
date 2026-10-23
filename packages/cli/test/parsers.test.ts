import { describe, expect, it } from "vitest";
import { parseCreatedSecret, parseDeployOutput, parseSecretList, parseStoreList, parseTable, parseWhoami } from "../src/lib/parsers.js";

const acc = (n: number) => ({ name: `Acme ${n}`, id: `${n}`.repeat(32).slice(0, 32) });

describe("parseWhoami", () => {
  it("1 account", () => {
    const out = JSON.stringify({ loggedIn: true, authType: "OAuth Token", email: "op@example.com", accounts: [acc(1)], tokenPermissions: ["workers:write"] });
    expect(parseWhoami(out)).toEqual({ loggedIn: true, email: "op@example.com", accounts: [acc(1)] });
  });
  it("N accounts, preceded by a log line", () => {
    const out = `⛅️ wrangler 4.152.0\n${JSON.stringify({ loggedIn: true, authType: "OAuth Token", email: null, accounts: [acc(1), acc(2), acc(3)] })}\n`;
    const r = parseWhoami(out);
    expect(r.loggedIn && r.accounts.map((a) => a.id)).toEqual([acc(1).id, acc(2).id, acc(3).id]);
    expect(r.loggedIn && r.email).toBeNull();
  });
  it("pretty-printed multi-line JSON (wrangler 4.152 real output)", () => {
    const out = `\u26c5\ufe0f wrangler 4.152.0\n${JSON.stringify({ loggedIn: true, authType: "OAuth Token", email: "op@example.com", accounts: [{ ...acc(1), type: "standard", settings: { enforce_twofactor: true } }], tokenPermissions: ["workers:write"] }, null, 4)}\n`;
    expect(parseWhoami(out)).toEqual({ loggedIn: true, email: "op@example.com", accounts: [acc(1)] });
  });
  it("0 accounts", () => {
    expect(parseWhoami(JSON.stringify({ loggedIn: true, email: "x@y", accounts: [] }))).toEqual({ loggedIn: true, email: "x@y", accounts: [] });
  });
  it("logged out: JSON on stdout or stderr", () => {
    expect(parseWhoami('{"loggedIn":false}')).toEqual({ loggedIn: false });
    expect(parseWhoami("", '✘ [ERROR] {"loggedIn":false}')).toEqual({ loggedIn: false });
    expect(() => parseWhoami("garbage", "boom")).toThrow(/no JSON/);
  });
});

const STORE_TABLE = `🔐 Listing stores...
┌─────────┬──────────────────────────────────┬──────────────────────────────────┬────────────────────────┬────────────────────────┐
│ Name    │ ID                               │ AccountID                        │ Created                │ Modified               │
├─────────┼──────────────────────────────────┼──────────────────────────────────┼────────────────────────┼────────────────────────┤
│ default │ 7b1e2f3a4c5d6e7f8091a2b3c4d5e6f7 │ 0123456789abcdef0123456789abcdef │ 10/22/2026, 6:00:00 PM │ 10/22/2026, 6:00:00 PM │
└─────────┴──────────────────────────────────┴──────────────────────────────────┴────────────────────────┴────────────────────────┘
`;
const SECRET_TABLE = `🔐 Listing secrets... (store-id: 7b1e2f3a4c5d6e7f8091a2b3c4d5e6f7, page: 1)
┌────────────────────────┬──────────────────────────────────────┬─────────┬─────────┬─────────┬────────────────────────┬────────────────────────┐
│ Name                   │ ID                                   │ Comment │ Scopes  │ Status  │ Created                │ Modified               │
├────────────────────────┼──────────────────────────────────────┼─────────┼─────────┼─────────┼────────────────────────┼────────────────────────┤
│ OIDC_KEY_k20261022ab12 │ 11111111-2222-3333-4444-555555555555 │         │ workers │ active  │ 10/22/2026, 6:00:00 PM │ 10/22/2026, 6:00:00 PM │
├────────────────────────┼──────────────────────────────────────┼─────────┼─────────┼─────────┼────────────────────────┼────────────────────────┤
│ OIDC_KEYSET            │ 66666666-7777-8888-9999-aaaaaaaaaaaa │         │ workers │ pending │ 10/22/2026, 6:00:00 PM │ 10/22/2026, 6:00:00 PM │
└────────────────────────┴──────────────────────────────────────┴─────────┴─────────┴─────────┴────────────────────────┴────────────────────────┘
`;

describe("tables", () => {
  it("store list", () => {
    expect(parseStoreList(STORE_TABLE)).toEqual([{ name: "default", id: "7b1e2f3a4c5d6e7f8091a2b3c4d5e6f7" }]);
  });
  it("secret list", () => {
    expect(parseSecretList(SECRET_TABLE)).toEqual([
      { name: "OIDC_KEY_k20261022ab12", id: "11111111-2222-3333-4444-555555555555", status: "active" },
      { name: "OIDC_KEYSET", id: "66666666-7777-8888-9999-aaaaaaaaaaaa", status: "pending" },
    ]);
  });
  it("empty / no table", () => {
    expect(parseTable("List request returned no secrets.")).toEqual([]);
    expect(parseSecretList("")).toEqual([]);
  });
});

describe("secret create + deploy", () => {
  it("Created secret!", () => {
    expect(parseCreatedSecret("🔐 Creating secret... (Name: OIDC_KEY_k1, Value: REDACTED, Scopes: workers, Comment: undefined)\n✅ Created secret! (ID: 11111111-2222-3333-4444-555555555555)\n")).toBe("11111111-2222-3333-4444-555555555555");
    expect(parseCreatedSecret("✘ [ERROR] boom")).toBeNull();
  });
  it("deploy ndjson wins", () => {
    const nd = `{"type":"wrangler-session","version":1}\n{"type":"deploy","version":1,"worker_name":"oidc-issuer","targets":["https://oidc-issuer.acme.workers.dev","oidc.example.com/*"]}\n`;
    expect(parseDeployOutput(nd, "")).toEqual(["https://oidc-issuer.acme.workers.dev", "oidc.example.com/*"]);
  });
  it("stdout fallback: Deployed ... triggers block", () => {
    const out = "Uploaded oidc-issuer (2.10 sec)\nDeployed oidc-issuer triggers (1.02 sec)\n  https://oidc-issuer.acme.workers.dev\n  oidc.example.com/*\nCurrent Version ID: abc\n";
    expect(parseDeployOutput(null, out)).toEqual(["https://oidc-issuer.acme.workers.dev", "oidc.example.com/*"]);
  });
  it("stdout fallback: bare regex", () => {
    expect(parseDeployOutput("not json", "see https://oidc-issuer.acme.workers.dev now and https://oidc-issuer.acme.workers.dev again")).toEqual(["https://oidc-issuer.acme.workers.dev"]);
    expect(parseDeployOutput(null, "")).toEqual([]);
  });
});
