export type Account = { name: string; id: string };
export type Whoami = { loggedIn: false } | { loggedIn: true; email: string | null; accounts: Account[] };

export function parseWhoami(stdout: string, stderr = ""): Whoami {
  // wrangler 4.152 pretty-prints the object over many lines; log lines may precede it.
  const start = stdout.search(/^\s*\{/m);
  let j: unknown;
  try { j = start >= 0 ? JSON.parse(stdout.slice(start).trim()) : undefined; } catch { j = undefined; }
  if (typeof j !== "object" || j === null) {
    if (/"loggedIn"\s*:\s*false/.test(stdout + stderr)) return { loggedIn: false };
    throw new Error("wrangler whoami --json: no JSON on stdout");
  }
  const o = j as { loggedIn?: unknown; email?: unknown; accounts?: unknown };
  if (o.loggedIn !== true) return { loggedIn: false };
  const accounts = Array.isArray(o.accounts)
    ? o.accounts.flatMap((a: unknown) => {
        const x = a as { name?: unknown; id?: unknown };
        return typeof x.name === "string" && typeof x.id === "string" ? [{ name: x.name, id: x.id }] : [];
      })
    : [];
  return { loggedIn: true, email: typeof o.email === "string" ? o.email : null, accounts };
}

/** cli-table3 box table -> rows keyed by header cell. */
export function parseTable(text: string): Record<string, string>[] {
  const rows = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("│"))
    .map((l) => l.split("│").slice(1, -1).map((c) => c.trim()));
  const head = rows[0];
  if (!head) return [];
  return rows.slice(1).map((cells) => Object.fromEntries(head.map((h, i) => [h, cells[i] ?? ""])));
}

export type Store = { name: string; id: string };
export function parseStoreList(stdout: string): Store[] {
  return parseTable(stdout).flatMap((r) => (r["Name"] && r["ID"] ? [{ name: r["Name"], id: r["ID"] }] : []));
}

export type Secret = { name: string; id: string; status: string };
export function parseSecretList(stdout: string): Secret[] {
  return parseTable(stdout).flatMap((r) => (r["Name"] && r["ID"] ? [{ name: r["Name"], id: r["ID"], status: r["Status"] ?? "" }] : []));
}

export function parseCreatedSecret(stdout: string): string | null {
  return /Created secret! \(ID: ([0-9a-f-]+)\)/.exec(stdout)?.[1] ?? null;
}

/** Deploy targets from WRANGLER_OUTPUT_FILE_PATH ndjson, else from stdout. */
export function parseDeployOutput(ndjson: string | null, stdout: string): string[] {
  for (const line of (ndjson ?? "").split("\n")) {
    if (!line.trim()) continue;
    let ev: unknown;
    try { ev = JSON.parse(line); } catch { continue; }
    const e = ev as { type?: unknown; targets?: unknown };
    if (e.type === "deploy" && Array.isArray(e.targets)) return e.targets.filter((t): t is string => typeof t === "string");
  }
  const lines = stdout.split("\n");
  const start = lines.findIndex((l) => /^Deployed .* triggers/.test(l));
  if (start >= 0) {
    const out: string[] = [];
    for (const l of lines.slice(start + 1)) {
      const m = /^\s+(\S+)$/.exec(l);
      if (!m) break;
      out.push(m[1] as string);
    }
    if (out.length > 0) return out;
  }
  return [...new Set(stdout.match(/https:\/\/[\w.-]+\.workers\.dev/g) ?? [])];
}
