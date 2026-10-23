import { type Config, type Env, KID_RE, policyFingerprint } from "./config.js";

export type PrivateJwk = {
  kty: "RSA"; alg: "RS256"; use: "sig"; kid: string;
  n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string;
};
export type PublicJwk = { kty: "RSA"; n: string; e: string; kid: string; alg: "RS256"; use: "sig" };

export type KeysetKey = PrivateJwk & { created: number; status: "next" | "active" | "retiring"; activateAt?: number; retireAt?: number };
export type Keyset = { v: 1; version: number; active: string; keys: KeysetKey[] };

export const RSA_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;
export const MEMBERS = ["alg", "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"] as const;
const B64URL = /^[A-Za-z0-9_-]+$/;
const BIG = ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const;
export const STATUSES = ["next", "active", "retiring"] as const;
const JWKS_ORDER = ["active", "next", "retiring"] as const;

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Exact member set, RS256/sig/RSA, base64url big members, kid regex. Returns null on any deviation. */
export function parsePrivateJwk(raw: unknown): PrivateJwk | null {
  if (typeof raw !== "object" || raw === null) return null;
  const j = raw as Record<string, unknown>;
  const keys = Object.keys(j).sort();
  if (keys.length !== MEMBERS.length || keys.some((k, i) => k !== MEMBERS[i])) return null;
  if (j["kty"] !== "RSA" || j["alg"] !== "RS256" || j["use"] !== "sig") return null;
  if (typeof j["kid"] !== "string" || !KID_RE.test(j["kid"])) return null;
  for (const m of BIG) if (typeof j[m] !== "string" || !B64URL.test(j[m] as string)) return null;
  return j as unknown as PrivateJwk;
}

/** Allow-list only: never spread the private JWK. */
export function publicJwk(j: PrivateJwk): PublicJwk {
  return { kty: "RSA", n: j.n, e: j.e, kid: j.kid, alg: "RS256", use: "sig" };
}

export async function sha256(s: string): Promise<string> {
  return b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

export const fingerprint = (k: { n: string; e: string }): Promise<string> => sha256(`${k.n}.${k.e}`);

const PROBE = new Uint8Array([0]);
/** Non-extractable import; null when the runtime rejects it, the modulus is short, or the key cannot sign for (n, e). */
export async function importPrivate(j: PrivateJwk): Promise<CryptoKey | null> {
  try {
    const key = await crypto.subtle.importKey("jwk", j, RSA_ALG, false, ["sign"]);
    if (((key.algorithm as { modulusLength?: number }).modulusLength ?? 0) < 2048) return null;
    // Round trip: importKey accepts a JWK whose private members belong to another key; sign then throws or verifies false.
    const pub = await crypto.subtle.importKey("jwk", publicJwk(j), RSA_ALG, false, ["verify"]);
    const sig = await crypto.subtle.sign(RSA_ALG, key, PROBE);
    return (await crypto.subtle.verify(RSA_ALG, pub, sig, PROBE)) ? key : null;
  } catch {
    return null;
  }
}

export function parseKeyset(raw: string): Keyset | null {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null) return null;
  const ks = v as Record<string, unknown>;
  if (ks["v"] !== 1 || typeof ks["version"] !== "number" || !Number.isInteger(ks["version"]) || typeof ks["active"] !== "string" || !Array.isArray(ks["keys"])) return null;
  if (ks["keys"].length > 3) return null;
  const keys: KeysetKey[] = [];
  for (const item of ks["keys"] as unknown[]) {
    if (typeof item !== "object" || item === null) return null;
    const { created, status, activateAt, retireAt, ...jwk } = item as Record<string, unknown>;
    const pk = parsePrivateJwk(jwk);
    if (!pk || typeof created !== "number" || !STATUSES.includes(status as never)) return null;
    if ((activateAt !== undefined && typeof activateAt !== "number") || (retireAt !== undefined && typeof retireAt !== "number")) return null;
    if (keys.some((k) => k.kid === pk.kid)) return null;
    const k: KeysetKey = { ...pk, created, status: status as KeysetKey["status"] };
    if (typeof activateAt === "number") k.activateAt = activateAt;
    if (typeof retireAt === "number") k.retireAt = retireAt;
    keys.push(k);
  }
  return { v: 1, version: ks["version"], active: ks["active"], keys };
}

export type Loaded = { active: { kid: string; key: CryptoKey } | null; published: PublicJwk[]; warnings: string[]; heal: boolean };

const MEMO_MS = 60_000;
let memo: { key: string; until: number; loaded: Loaded } | null = null;
const keyCache = new Map<string, CryptoKey>();

async function cachedImport(kid: string, j: PrivateJwk): Promise<CryptoKey | null> {
  const id = `${kid}:${await sha256(JSON.stringify(j))}`;
  const hit = keyCache.get(id);
  if (hit) return hit;
  const key = await importPrivate(j);
  if (key) keyCache.set(id, key);
  return key;
}

export function keyring(env: Env): DurableObjectStub<import("./keyring.js").KeyRing> {
  const ns = env.KEYRING as DurableObjectNamespace<import("./keyring.js").KeyRing>;
  return ns.get(ns.idFromName("default"));
}

async function loadManual(env: Env, cfg: Extract<Config, { mode: "manual" }>): Promise<{ key: string; loaded: Loaded }> {
  let raws: string[];
  try {
    raws = await Promise.all(cfg.kids.map((kid) => env[`OIDC_KEY_${kid}`]!.get()));
  } catch {
    // A failed read is an outage, not an empty slot (see keyring.ts runTick). Callers fail closed: public.ts -> 500 no-store, issueToken -> throws.
    throw new Error("keys unavailable");
  }
  const key = `manual:${cfg.activeKid}:${cfg.kids.join(",")}:${await sha256(raws.join("\n"))}`;
  if (memo && memo.key === key && Date.now() < memo.until) return { key, loaded: memo.loaded };
  const loaded: Loaded = { active: null, published: [], warnings: [], heal: false };
  const order = [cfg.activeKid, ...cfg.kids.filter((k) => k !== cfg.activeKid)];
  for (const kid of order) {
    const raw = raws[cfg.kids.indexOf(kid)] ?? "";
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(raw);
    } catch {
      /* broken slot */
    }
    const jwk = parsePrivateJwk(parsed);
    const cryptoKey = jwk && jwk.kid === kid ? await cachedImport(kid, jwk) : null;
    if (!jwk || !cryptoKey) {
      loaded.warnings.push(`key slot broken: kid=${kid}`);
      continue;
    }
    loaded.published.push(publicJwk(jwk));
    if (kid === cfg.activeKid) loaded.active = { kid, key: cryptoKey };
  }
  return { key, loaded };
}

async function loadAuto(env: Env, cfg: Extract<Config, { mode: "auto" }>): Promise<{ key: string; loaded: Loaded }> {
  let raw: string;
  try {
    raw = await (env.OIDC_KEYSET as SecretsStoreSecret).get();
  } catch {
    throw new Error("keys unavailable");
  }
  const key = `auto:${await sha256(raw)}`;
  if (memo && memo.key === key && Date.now() < memo.until) return { key, loaded: memo.loaded };
  const loaded: Loaded = { active: null, published: [], warnings: [], heal: true };
  const ks = parseKeyset(raw);
  if (!ks) {
    loaded.warnings.push("keyset missing or invalid");
    return { key, loaded };
  }
  const entries = await Promise.all(ks.keys.map(async (k) => ({ kid: k.kid, fp: await fingerprint(k) })));
  // The DO's status is the truth for order and for which key signs; the keyset's `active`/`status` are not trusted.
  const confirmed = new Map((await keyring(env).confirm(entries)).map((c) => [c.kid, c.status]));
  const pos = (kid: string): number => JWKS_ORDER.indexOf((confirmed.get(kid) ?? "retiring") as (typeof JWKS_ORDER)[number]);
  const ordered = [...ks.keys].sort((a, b) => pos(a.kid) - pos(b.kid));
  for (const k of ordered) {
    if (!confirmed.has(k.kid)) {
      loaded.warnings.push(`unconfirmed key dropped: kid=${k.kid}`);
      continue;
    }
    const cryptoKey = await cachedImport(k.kid, k);
    if (!cryptoKey) {
      loaded.warnings.push(`key slot broken: kid=${k.kid}`);
      continue;
    }
    loaded.published.push(publicJwk(k));
    if (confirmed.get(k.kid) === "active") loaded.active = { kid: k.kid, key: cryptoKey };
  }
  if (loaded.active) loaded.heal = false;
  else loaded.warnings.push("no confirmed active key");
  return { key, loaded };
}

/** Keys per the configured mode; memoised 60 s per (mode, raw secret hash). Warnings carry kids only. */
export async function loadKeys(env: Env, cfg: Config): Promise<Loaded> {
  const r = cfg.mode === "manual" ? await loadManual(env, cfg) : await loadAuto(env, cfg);
  if (!memo || memo.key !== r.key || Date.now() >= memo.until) {
    for (const w of r.loaded.warnings) console.warn(w);
    memo = { key: r.key, until: Date.now() + MEMO_MS, loaded: r.loaded };
  }
  return r.loaded;
}

const TICK_MS = 3_600_000;
const HEAL_MS = 10_000;
let lastTick: { at: number; fp: string } | null = null;
let behind = false; // DO reported propagation lag; retry at the heal cadence, never per request

/** Lazy tick: once per hour per isolate, on a policy change, or (rate-limited) when the signer has no usable active key. */
export function scheduleTick(env: Env, cfg: Config, ctx: ExecutionContext, heal: boolean): void {
  if (cfg.mode !== "auto") return;
  const fp = policyFingerprint(cfg.policy);
  const now = Date.now();
  const due = !lastTick || lastTick.fp !== fp || now - lastTick.at > TICK_MS || ((heal || behind) && now - lastTick.at > HEAL_MS);
  if (!due) return;
  lastTick = { at: now, fp };
  ctx.waitUntil(
    keyring(env)
      .tick(cfg.policy)
      .then((r) => {
        // Inside the propagation window the DO skips policy events; retry at the heal cadence (<= 6 ticks per window per isolate), not per request.
        behind = !r.changed && r.warnings.includes("keyset behind the DO; waiting for propagation");
      })
      .catch((e: unknown) => console.warn(`tick failed: ${e instanceof Error ? e.message : "error"}`)),
  );
}
