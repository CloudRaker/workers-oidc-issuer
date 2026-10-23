import type { KeyRing } from "./keyring.js";

/** Bindings and vars the signer may see. Validation happens in parseConfig; nothing here is trusted. */
export type Env = {
  ISSUER?: string;
  ROTATION?: string;
  ACTIVE_KID?: string;
  TOKEN_TTL_SECONDS?: string;
  CF_ACCOUNT_ID?: string;
  SECRETS_STORE_ID?: string;
  KEYSET_SECRET_NAME?: string;
  ROTATION_INTERVAL_HOURS?: string;
  ROTATION_GRACE_HOURS?: string;
  ROTATE_NONCE?: string;
  REVOKE_BEFORE?: string;
  RETIRE_KIDS?: string;
  OIDC_KEYSET?: SecretsStoreSecret;
  CF_API_TOKEN?: SecretsStoreSecret;
  KEYRING?: DurableObjectNamespace<KeyRing>;
  CF_API?: Fetcher;
  [binding: `OIDC_KEY_${string}`]: SecretsStoreSecret;
};

export const KID_RE = /^[a-z0-9]{1,32}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;

/** True only for a calendar-valid ISO-8601 timestamp; V8 rolls Feb 30 or 24:00 forward, so compare components. */
function isIsoInstant(v: string): boolean {
  const m = ISO.exec(v);
  if (!m || Number.isNaN(Date.parse(v))) return false;
  const [, y, mo, d, h, mi, s] = m as unknown as string[];
  return new Date(Date.UTC(+y!, +mo! - 1, +d!, +h!, +mi!, +s!)).toISOString().slice(0, 19) === v.slice(0, 19);
}

/** Message names the var only, never its value. */
export class ConfigError extends Error {
  constructor(name: string, why: string) {
    super(`misconfigured: ${name} ${why}`);
  }
}

export type Policy = { intervalHours: number; graceHours: number; rotateNonce: string; revokeBefore: string; retireKids: string[] };

export type Config = { issuer: string; ttl: number } & (
  | { mode: "manual"; activeKid: string; kids: string[] }
  | { mode: "auto"; accountId: string; storeId: string; secretName: string; policy: Policy }
);

function str(e: Record<string, unknown>, name: string, dflt?: string): string {
  const v = e[name];
  if (v === undefined) {
    if (dflt !== undefined) return dflt;
    throw new ConfigError(name, "is required");
  }
  if (typeof v !== "string") throw new ConfigError(name, "must be a string");
  return v;
}

function int(e: Record<string, unknown>, name: string, lo: number, hi: number, dflt?: string): number {
  const s = str(e, name, dflt);
  if (!/^\d{1,6}$/.test(s)) throw new ConfigError(name, "must be an integer");
  const n = Number(s);
  if (n < lo || n > hi) throw new ConfigError(name, `must be in [${lo}, ${hi}]`);
  return n;
}

function hasMethod(v: unknown, m: string): boolean {
  return typeof v === "object" && v !== null && typeof (v as Record<string, unknown>)[m] === "function";
}

export function parseConfig(env: Env): Config {
  const e = env as Record<string, unknown>;
  const issuer = str(e, "ISSUER");
  let origin: string;
  try {
    origin = new URL(issuer).origin;
  } catch {
    throw new ConfigError("ISSUER", "must be a URL");
  }
  if (!issuer.startsWith("https://") || origin !== issuer) throw new ConfigError("ISSUER", "must be an https origin with no path");
  const ttl = int(e, "TOKEN_TTL_SECONDS", 60, 3600, "300");
  const rotation = str(e, "ROTATION", "manual");
  if (rotation === "manual") {
    const kids = Object.keys(e).filter((k) => k.startsWith("OIDC_KEY_")).map((k) => k.slice(9)).sort();
    for (const kid of kids) {
      if (!KID_RE.test(kid)) throw new ConfigError(`OIDC_KEY_${kid}`, "has an invalid kid suffix");
      if (!hasMethod(e[`OIDC_KEY_${kid}`], "get")) throw new ConfigError(`OIDC_KEY_${kid}`, "is not a Secrets Store binding");
    }
    if (kids.length < 1 || kids.length > 10) throw new ConfigError("OIDC_KEY_*", "needs 1 to 10 bindings");
    const activeKid = str(e, "ACTIVE_KID");
    if (!KID_RE.test(activeKid)) throw new ConfigError("ACTIVE_KID", "must match the kid regex");
    if (!kids.includes(activeKid)) throw new ConfigError("ACTIVE_KID", "has no OIDC_KEY_ binding");
    return { mode: "manual", issuer, ttl, activeKid, kids };
  }
  if (rotation !== "auto") throw new ConfigError("ROTATION", 'must be "manual" or "auto"');
  for (const b of ["OIDC_KEYSET", "CF_API_TOKEN"]) if (!hasMethod(e[b], "get")) throw new ConfigError(b, "binding is missing");
  if (!hasMethod(e["KEYRING"], "idFromName")) throw new ConfigError("KEYRING", "binding is missing");
  const accountId = str(e, "CF_ACCOUNT_ID");
  const storeId = str(e, "SECRETS_STORE_ID");
  if (!HEX32.test(accountId)) throw new ConfigError("CF_ACCOUNT_ID", "must be 32 hex chars");
  if (!HEX32.test(storeId)) throw new ConfigError("SECRETS_STORE_ID", "must be 32 hex chars");
  const secretName = str(e, "KEYSET_SECRET_NAME", "OIDC_KEYSET");
  if (!/^[A-Za-z0-9_]{1,64}$/.test(secretName)) throw new ConfigError("KEYSET_SECRET_NAME", "has invalid characters");
  const intervalHours = int(e, "ROTATION_INTERVAL_HOURS", 24, 8760, "720");
  const graceHours = int(e, "ROTATION_GRACE_HOURS", 2, 168, "24");
  if (graceHours >= intervalHours / 2) throw new ConfigError("ROTATION_GRACE_HOURS", "must be less than half the interval");
  const revokeBefore = str(e, "REVOKE_BEFORE", "");
  if (revokeBefore !== "" && !isIsoInstant(revokeBefore)) throw new ConfigError("REVOKE_BEFORE", "must be empty or ISO-8601");
  const rotateNonce = str(e, "ROTATE_NONCE", "");
  if (rotateNonce.length > 64) throw new ConfigError("ROTATE_NONCE", "must be at most 64 chars");
  let retireKids: unknown;
  try {
    retireKids = JSON.parse(str(e, "RETIRE_KIDS", "[]"));
  } catch {
    throw new ConfigError("RETIRE_KIDS", "must be a JSON array");
  }
  if (!Array.isArray(retireKids) || !retireKids.every((k) => typeof k === "string" && KID_RE.test(k))) throw new ConfigError("RETIRE_KIDS", "must be a JSON array of kids");
  return { mode: "auto", issuer, ttl, accountId, storeId, secretName, policy: { intervalHours, graceHours, rotateNonce, revokeBefore, retireKids } };
}

export function policyFromEnv(env: Env): Policy {
  const cfg = parseConfig(env);
  if (cfg.mode !== "auto") throw new ConfigError("ROTATION", "is not auto");
  return cfg.policy;
}

/** Changes when a deploy changed a policy event var; drives the lazy tick. */
export function policyFingerprint(p: Policy): string {
  return JSON.stringify([p.rotateNonce, p.revokeBefore, p.retireKids]);
}
