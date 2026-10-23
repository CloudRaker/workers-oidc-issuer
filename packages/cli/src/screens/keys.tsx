import { randomBytes } from "node:crypto";
import { Box, Text } from "ink";
import { useCallback, useEffect, useState } from "react";
import { FlowView, useFlow } from "../flow.js";
import { fetchJwks, pollJwks } from "../lib/http.js";
import { addSecretBinding, removeSecretBinding, setActiveKid, setVar, type Summary } from "../lib/jsonc.js";
import { buildJwksTable, type Jwks, type JwksRow } from "../lib/jwks.js";
import { generatePrivateJwk } from "../lib/keygen.js";
import { assertNewKid, newManualKid } from "../lib/kid.js";
import { intInRange } from "../lib/validators.js";
import { Menu, NavContext, Table, useNav } from "../ui.js";
import { PENDING_ISSUER, createSecret, deploy, listSecrets, probeOrigin, readConfig, readSummary, writeConfig, type Flow } from "./ops.js";

const ONE_HOUR = "wait >= 1h for JWKS caches (Cache-Control max-age=3600) before the next step";
export const ROTATION_STEPS = "Full rotation: Add -> wait 1h -> Promote -> wait 1h -> Remove.";

function setVars(workerDir: string, vars: Record<string, string>): void {
  let t = readConfig(workerDir);
  for (const [k, v] of Object.entries(vars)) t = setVar(t, k, v);
  writeConfig(workerDir, t);
}

/* ---------- manual mode actions ---------- */

/** Writes the config and deploys; a failed deploy restores the file so wrangler.jsonc never claims a state the Worker does not have. */
async function writeAndDeploy(f: Flow, next: (cfg: string) => string): Promise<void> {
  const before = readConfig(f.workerDir);
  writeConfig(f.workerDir, next(before));
  try {
    await deploy(f);
  } catch (e) {
    writeConfig(f.workerDir, before);
    throw e;
  }
}

export async function addKey(f: Flow, s: Summary): Promise<void> {
  const storeId = s.storeId;
  if (!storeId || storeId === "REPLACE_ME") throw new Error("no Secrets Store id in wrangler.jsonc; run Setup first");
  const kid = newManualKid();
  assertNewKid(kid, s.kids);
  f.log(`generating RSA-2048 key ${kid} in memory`);
  const jwk = await generatePrivateJwk(kid);
  await createSecret(f, storeId, `OIDC_KEY_${kid}`, JSON.stringify(jwk));
  await writeAndDeploy(f, (c) => addSecretBinding(c, { binding: `OIDC_KEY_${kid}`, store_id: storeId, secret_name: `OIDC_KEY_${kid}` }));
  f.log(`${kid} is published; ${ONE_HOUR} (Promote)`);
}

export async function promoteKey(f: Flow, s: Summary): Promise<void> {
  const others = s.kids.filter((k) => k !== s.activeKid);
  if (others.length === 0) throw new Error("no other published kid to promote; Add one first");
  const kid = await f.menu("Promote which kid to ACTIVE?", others.map((k) => ({ label: k, value: k })));
  await writeAndDeploy(f, (c) => setActiveKid(c, kid));
  f.log(`${kid} is ACTIVE; ${ONE_HOUR} (Remove the old one)`);
}

export async function removeKey(f: Flow, s: Summary): Promise<void> {
  const others = s.kids.filter((k) => k !== s.activeKid);
  if (others.length === 0) throw new Error("only the ACTIVE kid is published; it cannot be removed");
  const kid = await f.menu("Remove which kid? (ACTIVE is refused)", others.map((k) => ({ label: k, value: k })));
  if (kid === s.activeKid) throw new Error("refusing to remove the ACTIVE kid");
  if (!(await f.confirm(`Remove ${kid}? Only do this >= 1h after it stopped being ACTIVE.`))) return;
  // a failed deploy restores the binding: Remove can be retried and the secret is not orphaned
  await writeAndDeploy(f, (c) => removeSecretBinding(c, `OIDC_KEY_${kid}`));
  const storeId = s.storeId ?? "";
  const list = await listSecrets(f, storeId);
  const sec = list.find((x) => x.name === `OIDC_KEY_${kid}`);
  if (!sec) throw new Error(`binding OIDC_KEY_${kid} removed and deployed, but no secret named OIDC_KEY_${kid} is in store ${storeId}; check with \`wrangler secrets-store secret list ${storeId} --remote --per-page 100\``);
  await f.wrangler(["secrets-store", "secret", "delete", storeId, "--secret-id", sec.id, "--remote"]);
  f.log(`${kid} removed from the Worker and the store`);
}

/* ---------- auto mode actions ---------- */

const kidsOf = (j: Jwks) => j.keys.map((k) => k.kid).join(",");
const NO_JWKS: Jwks = { keys: [] };

/** Deploys the policy change, fetches the JWKS to trigger the lazy tick and waits for the key set to change. */
async function deployAndTrigger(f: Flow, issuer: string, before: Jwks): Promise<JwksRow[]> {
  const targets = await deploy(f);
  const probe = probeOrigin(f, issuer, targets);
  f.log("fetching the JWKS to trigger the KeyRing tick (up to 45 s)");
  const after = await pollJwks(probe, (j) => kidsOf(j) !== kidsOf(before), 45_000);
  if (!after) { f.log("deployed, but the JWKS is unreachable from here; the KeyRing applies the policy on the next request or cron tick"); return []; }
  if (kidsOf(after) === kidsOf(before)) f.log("the key set has not changed yet; check Keys again in a minute");
  return buildJwksTable(after);
}

export async function rotateNow(f: Flow, issuer: string, before: Jwks): Promise<JwksRow[]> {
  const rows = buildJwksTable(before);
  if (rows.some((r) => r.role === "next")) {
    f.log("a `next` key is already published; the KeyRing ignores a new ROTATE_NONCE until it is promoted. Nothing deployed.");
    return rows;
  }
  setVars(f.workerDir, { ROTATE_NONCE: randomBytes(4).toString("hex") });
  f.log("ROTATE_NONCE set: a `next` key appears now and becomes active after ROTATION_GRACE_HOURS");
  return deployAndTrigger(f, issuer, before);
}

export async function emergencyRevoke(f: Flow, issuer: string, before: Jwks): Promise<JwksRow[] | null> {
  if (!(await f.confirm("EMERGENCY REVOKE: every current key is retired immediately and a new active key is generated. Continue?"))) return null;
  if (!(await f.confirm("In-flight tokens will fail verification within seconds; consumers get a fresh key on their next getToken call. Really continue?"))) return null;
  setVars(f.workerDir, { REVOKE_BEFORE: new Date().toISOString() });
  return deployAndTrigger(f, issuer, before);
}

export async function retireKey(f: Flow, issuer: string, before: Jwks): Promise<JwksRow[] | null> {
  const rows = buildJwksTable(before);
  const others = rows.filter((r) => r.role !== "active");
  if (others.length === 0) throw new Error("only the active key is served; nothing to retire");
  const kid = await f.menu("Retire which key? (active is refused by the KeyRing)", others.map((r) => ({ label: r.kid, value: r.kid, hint: r.role })));
  setVars(f.workerDir, { RETIRE_KIDS: JSON.stringify([kid]) });
  const out = await deployAndTrigger(f, issuer, before);
  // ponytail: RETIRE_KIDS stays set; the KeyRing ignores kids it no longer has, and the next Retire overwrites it.
  f.log("RETIRE_KIDS is left in wrangler.jsonc; unknown kids are ignored by the KeyRing");
  return out;
}

export async function editSchedule(f: Flow, issuer: string, before: Jwks): Promise<JwksRow[]> {
  const interval = await f.text("ROTATION_INTERVAL_HOURS (24..8760)", { validate: (s) => (intInRange(s, 24, 8760) === null ? "integer in [24, 8760]" : null) });
  const grace = await f.text("ROTATION_GRACE_HOURS (2..168, less than half the interval)", {
    validate: (s) => { const g = intInRange(s, 2, 168); return g === null || g >= Number(interval) / 2 ? "integer in [2, 168] and < interval/2" : null; },
  });
  setVars(f.workerDir, { ROTATION_INTERVAL_HOURS: interval, ROTATION_GRACE_HOURS: grace });
  await deploy(f);
  return buildJwksTable(before);
}

/* ---------- screen ---------- */

export function Keys(p: { workerDir: string }) {
  const nav = useNav();
  const { state, run, reset } = useFlow(p.workerDir);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [jwks, setJwks] = useState<Jwks | { error: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const reload = useCallback(() => {
    try {
      const s = readSummary(p.workerDir);
      setSummary(s);
      if (s.mode === "auto") {
        if (!s.issuer || s.issuer === PENDING_ISSUER) setJwks({ error: "vars.ISSUER is not set; run Setup or Deploy" });
        else fetchJwks(s.issuer).then(setJwks).catch((e: unknown) => setJwks({ error: e instanceof Error ? e.message : String(e) }));
      }
    } catch (e) { setLoadError(e instanceof Error ? e.message : String(e)); }
  }, [p.workerDir]);
  useEffect(reload, [reload]);

  const act = (fn: (f: Flow) => Promise<unknown>) => { void run(async (f) => { await fn(f); }); };
  const backToList = useCallback(() => { reset(); reload(); }, [reset, reload]);

  if (state.status !== "idle") {
    return (
      <NavContext.Provider value={{ back: backToList, quit: nav.quit }}>
        <FlowView state={state}><Text bold>Keys</Text></FlowView>
      </NavContext.Provider>
    );
  }
  if (loadError) return <Menu title={`Keys: ${loadError}`} items={[{ label: "Back", value: "back" }]} onSelect={nav.back} onCancel={nav.back} />;
  if (!summary) return <Text>reading wrangler.jsonc...</Text>;

  if (summary.mode === "manual") {
    const s = summary;
    return (
      <Box flexDirection="column">
        <Text bold>Keys (manual mode)</Text>
        <Table head={["kid", "role"]} rows={s.kids.map((k) => [k, k === s.activeKid ? "ACTIVE" : "PUBLISHED"])} />
        <Text dimColor>{ROTATION_STEPS}</Text>
        <Menu
          title="Action"
          items={[
            { label: "Add key", value: "add", hint: "generate, upload, bind, deploy" },
            { label: "Promote key", value: "promote", hint: "set ACTIVE_KID, deploy" },
            { label: "Remove key", value: "remove", hint: "unbind, deploy, delete secret" },
          ]}
          onSelect={(v) => act((f) => (v === "add" ? addKey(f, s) : v === "promote" ? promoteKey(f, s) : removeKey(f, s)))}
          onCancel={nav.back}
        />
      </Box>
    );
  }

  const issuer = summary.issuer ?? "";
  const rows = jwks && !("error" in jwks) ? buildJwksTable(jwks) : [];
  const liveJwks = jwks && !("error" in jwks) ? jwks : null;
  // revoke and schedule only write vars and deploy; they must work while the issuer is broken or unreachable
  const show = (fn: (f: Flow, issuer: string, before: Jwks) => Promise<JwksRow[] | null>, needsJwks: boolean) => act(async (f) => {
    if (needsJwks && !liveJwks) throw new Error("JWKS not loaded; fix the issuer first");
    const out = await fn(f, issuer, liveJwks ?? NO_JWKS); // an empty baseline makes deployAndTrigger stop at the first served key set
    if (out) for (const r of out) f.log(`${r.kid}  ${r.fp}  ${r.age}  ${r.role}`);
  });
  return (
    <Box flexDirection="column">
      <Text bold>Keys (auto mode) {issuer}</Text>
      {jwks === null ? <Text>fetching JWKS...</Text> : "error" in jwks ? <Text color="red">{jwks.error}</Text> : <Table head={["kid", "fingerprint", "age", "role"]} rows={rows.map((r) => [r.kid, r.fp, r.age, r.role])} />}
      <Menu
        title="Action"
        items={[
          { label: "Rotate now", value: "rotate", hint: "graceful: next key now, active after the grace period" },
          { label: "Emergency revoke", value: "revoke", hint: "retire everything now, double confirm" },
          { label: "Retire key", value: "retire", hint: "drop one non-active key" },
          { label: "Edit schedule", value: "schedule", hint: "interval / grace hours" },
          { label: "Refresh", value: "refresh" },
        ]}
        onSelect={(v) => (v === "refresh" ? reload()
          : v === "rotate" ? show(rotateNow, true)
          : v === "revoke" ? show(emergencyRevoke, false)
          : v === "retire" ? show(retireKey, true)
          : show(editSchedule, false))}
        onCancel={nav.back}
      />
    </Box>
  );
}
