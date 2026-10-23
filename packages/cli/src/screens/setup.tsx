import { Text } from "ink";
import { useEffect } from "react";
import { FlowView, useFlow } from "../flow.js";
import { EMPTY_KEYSET, validateToken } from "../lib/cfapi.js";
import { pollJwks } from "../lib/http.js";
import { addSecretBinding, enableAutoMode, enableManualMode, parseConfig, removeSecretBinding, setIssuer, bindingKids } from "../lib/jsonc.js";
import { generatePrivateJwk } from "../lib/keygen.js";
import { assertNewKid, newManualKid } from "../lib/kid.js";
import { validateIssuer } from "../lib/validators.js";
import { PENDING_ISSUER, createSecret, deploy, ensureAccount, ensureStore, issuerFromTargets, listSecrets, probeOrigin, readConfig, readSummary, upsertSecret, writeConfig, type Flow } from "./ops.js";

export async function runSetup(f: Flow, onDeployed: (targets: string[]) => void): Promise<void> {
  const { accountId } = await ensureAccount(f);
  const storeId = await ensureStore(f);
  f.log(`Secrets Store ${storeId}`);

  const mode = await f.menu("Key management mode", [
    { label: "manual (recommended)", value: "manual", hint: "keys made on this machine, uploaded over stdin; no API token needed" },
    { label: "auto", value: "auto", hint: "keys generated inside Cloudflare, rotated on a schedule; needs an API token with Account > Secrets Store > Edit" },
  ]);
  const cur = readSummary(f.workerDir).issuer;
  const keep = cur && !validateIssuer(cur) ? [{ label: `keep ${cur}`, value: "keep" }] : [];
  const issuerChoice = await f.menu("ISSUER (pinned in your cloud provider's config; use a custom domain for production)", [
    ...keep,
    { label: "workers.dev URL from the first deploy", value: "workers" },
    { label: "custom domain", value: "custom", hint: "https origin, e.g. https://oidc.example.com" },
  ]);
  const issuer = issuerChoice === "keep" ? (cur as string) : issuerChoice === "custom" ? await f.text("ISSUER origin", { validate: validateIssuer }) : PENDING_ISSUER;

  let text = readConfig(f.workerDir);
  const wasAuto = parseConfig(text).vars?.["ROTATION"] === "auto"; // captured before enableManualMode strips the auto vars
  for (const b of parseConfig(text).secrets_store_secrets ?? []) if (b.store_id === "REPLACE_ME") text = removeSecretBinding(text, b.binding);
  const existing = await listSecrets(f, storeId);
  if (mode === "manual") {
    const cfg = parseConfig(text);
    const kids = bindingKids(cfg);
    const active = cfg.vars?.["ACTIVE_KID"];
    if (active && kids.includes(active)) {
      // a live manual issuer keeps its keys: activating a fresh kid here would skip the 1h JWKS-cache wait
      f.log(`keeping existing OIDC_KEY_* bindings (${kids.join(", ")}) and ACTIVE_KID ${active}; use Keys > Add / Promote to rotate (1h wait between steps)`);
      text = enableManualMode(text, { storeId });
    } else {
      const kid = newManualKid();
      assertNewKid(kid, kids);
      f.log(`generating RSA-2048 key ${kid} in memory`);
      const jwk = await generatePrivateJwk(kid);
      await createSecret(f, storeId, `OIDC_KEY_${kid}`, JSON.stringify(jwk));
      text = enableManualMode(text, { storeId, kid });
    }
  } else {
    f.log("Create an API token at https://dash.cloudflare.com/profile/api-tokens: Create Custom Token -> Permissions: Account > Secrets Store > Edit -> Account Resources: this account only -> optional TTL.");
    let token = await f.text("Paste the API token (input is masked)", { mask: true, validate: (s) => (s.trim().length < 20 ? "that is too short for an API token" : null) });
    token = token.trim();
    // never reset an existing keyset: it holds the only copy of the live private keys (the DO stores none)
    if (existing.some((s) => s.name === "OIDC_KEYSET")) f.log("reusing existing OIDC_KEYSET; the KeyRing rewrites it on its next tick");
    else await createSecret(f, storeId, "OIDC_KEYSET", EMPTY_KEYSET); // via wrangler OAuth, before the probe
    f.log("validating the token against api.cloudflare.com (list store, write OIDC_KEYSET scopes)");
    const check = await validateToken({ accountId, storeId, token, keysetSecretName: "OIDC_KEYSET" });
    if (!check.ok) { token = ""; throw new Error(`API token check failed: ${check.reason}`); }
    await upsertSecret(f, storeId, "OIDC_CF_API_TOKEN", token, existing);
    token = ""; // ponytail: JS strings cannot be zeroed; the only reference is dropped here
    text = enableAutoMode(text, { accountId, storeId });
  }
  // never write the placeholder: the shipped wrangler.jsonc already holds it, and a live ISSUER must survive a failed deploy
  if (issuer !== PENDING_ISSUER) text = setIssuer(text, issuer);
  writeConfig(f.workerDir, text);
  f.log(mode === "auto" ? "wrote wrangler.jsonc (ROTATION=auto; existing schedule and nonce kept)" : "wrote wrangler.jsonc (ROTATION=manual)");

  let targets = await deploy(f);
  let finalIssuer = issuer;
  if (issuer === PENDING_ISSUER) {
    const derived = issuerFromTargets(targets);
    if (!derived) throw new Error("deploy reported no workers.dev URL; set vars.ISSUER in wrangler.jsonc and deploy again");
    finalIssuer = derived;
    writeConfig(f.workerDir, setIssuer(readConfig(f.workerDir), derived));
    f.log(`ISSUER=${derived}; deploying again`);
    targets = await deploy(f);
  }
  onDeployed(targets);
  if (mode === "manual" && wasAuto) {
    // only after the manual deploy: until then the running auto-mode Worker still binds both secrets
    for (const n of ["OIDC_CF_API_TOKEN", "OIDC_KEYSET"]) {
      const sec = existing.find((x) => x.name === n);
      if (!sec) continue;
      await f.wrangler(["secrets-store", "secret", "delete", storeId, "--secret-id", sec.id, "--remote"]);
      f.log(`${n} deleted from the store (left over from auto mode)`);
    }
    if (existing.some((x) => x.name === "OIDC_CF_API_TOKEN")) f.log("the auto-mode API token is still valid: revoke it at https://dash.cloudflare.com/profile/api-tokens");
  } else if (mode === "manual" && existing.some((x) => x.name === "OIDC_KEYSET" || x.name === "OIDC_CF_API_TOKEN")) {
    // the store is account-wide: another issuer Worker in auto mode owns these, and the keyset is its only copy of the keys
    f.log("OIDC_KEYSET / OIDC_CF_API_TOKEN exist in the store but this config was not in auto mode; left untouched (another issuer may own them)");
  }
  if (mode === "auto") {
    const probe = probeOrigin(f, finalIssuer, targets);
    f.log(`fetching ${probe}/.well-known/jwks.json to trigger the first key generation (up to 60 s)`);
    const j = await pollJwks(probe, (x) => x.keys.length > 0, 60_000);
    if (!j) throw new Error(`${probe}/.well-known/jwks.json was unreachable for 60 s; the hourly cron still runs the first tick, or retry Verify once the host is routed`);
    if (j.keys.length === 0) throw new Error("no key appeared in the JWKS within 60 s; check `wrangler tail` for KeyRing errors");
    f.log(`JWKS serves ${j.keys.map((k) => k.kid).join(", ")}`);
  }
  f.log("setup complete");
}

export function Setup(p: { workerDir: string; onDeployed: (t: string[]) => void; onDone: () => void }) {
  const { state, run } = useFlow(p.workerDir);
  useEffect(() => { void run((f) => runSetup(f, p.onDeployed)).then((s) => { if (s === "done") p.onDone(); }); }, [run]); // eslint-disable-line react-hooks/exhaustive-deps
  return <FlowView state={state}><Text bold>Setup</Text></FlowView>;
}
