import { mkdtempSync } from "node:fs";
import NodeModule from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { redact, resolveWranglerBin, runWrangler, spawnNode } from "../src/lib/wrangler.js";

const fake = fileURLToPath(new URL("./fixtures/fake-wrangler.cjs", import.meta.url));
const splitWriter = fileURLToPath(new URL("./fixtures/split-writer.cjs", import.meta.url));
const cwd = fileURLToPath(new URL("./fixtures/", import.meta.url));

describe("spawnNode", () => {
  it("passes args, env CI=1, stdin as one line then EOF, and redacts streamed output", async () => {
    const seen: string[] = [];
    const r = await spawnNode(fake, ["secrets-store", "secret", "create"], cwd, { stdin: "hunter2-value", onOutput: (l) => seen.push(l) });
    expect(r.code).toBe(0);
    const first = JSON.parse(r.stdout.split("\n")[0] as string) as Record<string, unknown>;
    expect(first).toEqual({ args: ["secrets-store", "secret", "create"], CI: "1", LOG: "log", M: "false", SAN: "true", WL: "false", stdinLen: "hunter2-value\n".length });
    expect(seen.join("\n")).not.toContain("SECRETSECRET");
    expect(seen.join("\n")).toContain('"d":"[redacted]"');
    expect(seen.join("\n")).toContain("Bearer [redacted]");
    expect(seen.join("\n")).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
  });
  it("no stdin option still closes stdin; non-zero exit propagates", async () => {
    const r = await spawnNode(fake, ["fail"], cwd);
    expect(r.code).toBe(3);
    expect((JSON.parse(r.stdout.split("\n")[0] as string) as { stdinLen: number; LOG?: string }).stdinLen).toBe(0);
    expect((JSON.parse(r.stdout.split("\n")[0] as string) as { LOG?: string }).LOG).toBe("log");
  });
  it("pins sanitizer, log level and disk logs for stdin commands even when the parent env says otherwise", async () => {
    const prev = { s: process.env["WRANGLER_LOG_SANITIZE"], w: process.env["WRANGLER_WRITE_LOGS"], l: process.env["WRANGLER_LOG"] };
    process.env["WRANGLER_LOG_SANITIZE"] = "false";
    process.env["WRANGLER_WRITE_LOGS"] = "true";
    process.env["WRANGLER_LOG"] = "debug";
    try {
      const r = await spawnNode(fake, ["secrets-store", "secret", "create"], cwd, { stdin: "v", env: { WRANGLER_LOG_SANITIZE: "false", WRANGLER_LOG: "error" } });
      const first = JSON.parse(r.stdout.split("\n")[0] as string) as { SAN?: string; WL?: string; LOG?: string };
      expect(first.SAN).toBe("true");
      expect(first.WL).toBe("false");
      expect(first.LOG).toBe("log");
      const r2 = await spawnNode(fake, ["deploy"], cwd);
      expect((JSON.parse(r2.stdout.split("\n")[0] as string) as { SAN?: string }).SAN).toBe("true");
      // JSON-parsed commands: "debug" would put log lines on stdout around the whoami JSON
      const r3 = await spawnNode(fake, ["whoami", "--json"], cwd);
      expect((JSON.parse(r3.stdout.split("\n")[0] as string) as { LOG?: string }).LOG).toBe("log");
    } finally {
      if (prev.s === undefined) delete process.env["WRANGLER_LOG_SANITIZE"]; else process.env["WRANGLER_LOG_SANITIZE"] = prev.s;
      if (prev.w === undefined) delete process.env["WRANGLER_WRITE_LOGS"]; else process.env["WRANGLER_WRITE_LOGS"] = prev.w;
      if (prev.l === undefined) delete process.env["WRANGLER_LOG"]; else process.env["WRANGLER_LOG"] = prev.l;
    }
  });
  it("never forwards CLOUDFLARE_ACCOUNT_ID or its CF_ACCOUNT_ID alias, even from o.env", async () => {
    const prev = { a: process.env["CLOUDFLARE_ACCOUNT_ID"], b: process.env["CF_ACCOUNT_ID"] };
    process.env["CLOUDFLARE_ACCOUNT_ID"] = "0".repeat(32);
    process.env["CF_ACCOUNT_ID"] = "1".repeat(32);
    try {
      const r = await spawnNode(fake, ["whoami", "--json"], cwd, { env: { CLOUDFLARE_ACCOUNT_ID: "2".repeat(32) } });
      const first = JSON.parse(r.stdout.split("\n")[0] as string) as { CFA?: string; CFA2?: string };
      expect(first.CFA).toBeUndefined();
      expect(first.CFA2).toBeUndefined();
    } finally {
      if (prev.a === undefined) delete process.env["CLOUDFLARE_ACCOUNT_ID"]; else process.env["CLOUDFLARE_ACCOUNT_ID"] = prev.a;
      if (prev.b === undefined) delete process.env["CF_ACCOUNT_ID"]; else process.env["CF_ACCOUNT_ID"] = prev.b;
    }
  });
  it("redacts a token and a private member that arrive split over two data chunks; last line flushed on close", async () => {
    const seen: string[] = [];
    const r = await spawnNode(splitWriter, [], cwd, { onOutput: (l) => seen.push(l) });
    expect(r.code).toBe(0);
    expect(seen).toEqual(["Authorization: Bearer [redacted]", '{"kid":"k1","d":"[redacted]"}']);
    expect(seen.join("\n")).not.toContain("B".repeat(30));
  });
});

describe("redact", () => {
  it("masks private members and long tokens, keeps short ids", () => {
    expect(redact('{"kid":"k1","d":"x","p":"y","n":"z"}')).toBe('{"kid":"k1","d":"[redacted]","p":"[redacted]","n":"z"}');
    expect(redact("id 11111111-2222-3333-4444-555555555555 ok")).toBe("id 11111111-2222-3333-4444-555555555555 ok");
    expect(redact(`tok ${"A".repeat(40)}`)).toBe("tok [redacted]");
  });
});

describe("resolveWranglerBin", () => {
  it("finds the worker package's wrangler", () => {
    const bin = resolveWranglerBin(fileURLToPath(new URL("../../worker/", import.meta.url)));
    expect(bin).toMatch(/wrangler\/bin\/wrangler\.js$/);
  });
  it("runWrangler rejects, never throws synchronously, when wrangler is not resolvable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "oidc-nowrangler-"));
    // vitest puts the pnpm store on NODE_PATH, which makes wrangler resolvable from any directory; drop it for this test
    const Module = NodeModule as unknown as { _initPaths(): void };
    const prev = process.env["NODE_PATH"];
    delete process.env["NODE_PATH"];
    Module._initPaths();
    try {
      await expect(runWrangler(dir, ["whoami", "--json"])).rejects.toThrow(/wrangler is not installed/);
    } finally {
      if (prev !== undefined) process.env["NODE_PATH"] = prev;
      Module._initPaths();
    }
  });
});
