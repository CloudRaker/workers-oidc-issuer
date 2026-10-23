import { Box, Text } from "ink";
import { useEffect, useState } from "react";
import { fetchJwks } from "../lib/http.js";
import type { Summary } from "../lib/jsonc.js";
import { parseWhoami, type Whoami } from "../lib/parsers.js";
import { runWrangler } from "../lib/wrangler.js";
import { Menu } from "../ui.js";
import { readSummary } from "./ops.js";

export type ScreenName = "setup" | "keys" | "deploy" | "snippet" | "verify" | "account";

export function Home(p: { workerDir: string; onGo: (s: ScreenName) => void; onQuit: () => void }) {
  const [auth, setAuth] = useState<Whoami | { error: string } | null>(null);
  const [cfg, setCfg] = useState<Summary | { error: string } | null>(null);
  const [kids, setKids] = useState<string[] | null>(null);
  useEffect(() => {
    let live = true;
    runWrangler(p.workerDir, ["whoami", "--json"])
      .then((r) => {
        if (!live) return;
        try { setAuth(parseWhoami(r.stdout, r.stderr)); } catch (e) {
          setAuth({ error: r.stderr.trim().split("\n").filter(Boolean).pop() ?? (e instanceof Error ? e.message : String(e)) });
        }
      })
      .catch((e: unknown) => live && setAuth({ error: e instanceof Error ? e.message : String(e) }));
    try {
      const s = readSummary(p.workerDir);
      setCfg(s);
      if (s.mode === "auto" && s.issuer) fetchJwks(s.issuer).then((j) => live && setKids(j.keys.map((k) => k.kid))).catch(() => live && setKids([]));
    } catch (e) { setCfg({ error: e instanceof Error ? e.message : String(e) }); }
    return () => { live = false; };
  }, [p.workerDir]);

  const authLine = auth === null ? "checking wrangler login..." : "error" in auth ? `auth: ${auth.error}` : !auth.loggedIn ? "not logged in (run `wrangler login`)" : `logged in as ${auth.email ?? "(no email)"}; ${auth.accounts.length} account(s)`;
  const pinned = cfg && !("error" in cfg) ? cfg.accountId : undefined;
  const accountLine = auth && !("error" in auth) && auth.loggedIn && auth.accounts.length > 1 && !pinned ? "warning: several accounts, none pinned; run Setup or Change account" : pinned ? `account_id ${pinned}` : null;
  return (
    <Box flexDirection="column">
      <Text bold>workers-oidc-issuer</Text>
      <Text>{authLine}</Text>
      {accountLine ? <Text {...(accountLine.startsWith("warning") ? { color: "yellow" } : {})}>{accountLine}</Text> : null}
      {cfg === null ? null : "error" in cfg ? <Text color="red">{cfg.error}</Text> : (
        <Text>
          worker {cfg.name ?? "?"} | issuer {cfg.issuer ?? "(unset)"} | mode {cfg.mode} | {cfg.mode === "manual" ? `active ${cfg.activeKid ?? "(none)"}; published ${cfg.kids.join(", ") || "(none)"}` : `keyset kids ${kids === null ? "..." : kids.join(", ") || "(none served)"}`}
        </Text>
      )}
      <Box marginTop={1}>
        <Menu
          title="Menu"
          items={[
            { label: "Setup", value: "setup", hint: "login, store, mode, first key, deploy" },
            { label: "Keys", value: "keys", hint: "list, add, promote, remove / rotate" },
            { label: "Deploy", value: "deploy" },
            { label: "Consumer snippet", value: "snippet" },
            { label: "Verify", value: "verify" },
            { label: "Change account", value: "account" },
          ]}
          onSelect={(v) => p.onGo(v as ScreenName)}
          onCancel={p.onQuit}
        />
      </Box>
    </Box>
  );
}
