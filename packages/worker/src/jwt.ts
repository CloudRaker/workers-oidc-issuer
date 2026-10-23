import { type Env, parseConfig } from "./config.js";
import { b64url, loadKeys, RSA_ALG, scheduleTick } from "./keys.js";

export type Props = { sub: string; aud: string[] };
export type TokenOpts = { aud: string; ttl?: number };
export type TokenResult = { token: string; expiresAt: number; kid: string };

const PRINTABLE = /^[\x20-\x7e]+$/;

export function validateProps(p: unknown): Props {
  if (typeof p !== "object" || p === null) throw new Error("invalid props: not an object");
  const { sub, aud } = p as Record<string, unknown>;
  if (typeof sub !== "string" || sub.length === 0 || sub.length > 255 || !PRINTABLE.test(sub)) throw new Error("invalid props: sub");
  if (!Array.isArray(aud) || aud.length === 0 || !aud.every((a) => typeof a === "string" && a.length > 0 && a.length <= 512)) throw new Error("invalid props: aud");
  return { sub, aud: aud as string[] };
}

function validateOpts(o: unknown): TokenOpts {
  if (typeof o !== "object" || o === null) throw new Error("invalid opts: not an object");
  const { aud, ttl } = o as Record<string, unknown>;
  if (typeof aud !== "string" || aud.length === 0) throw new Error("invalid opts: aud");
  if (ttl !== undefined && (typeof ttl !== "number" || !Number.isInteger(ttl))) throw new Error("invalid opts: ttl must be an integer");
  return ttl === undefined ? { aud } : { aud, ttl };
}

const enc = (o: unknown): string => b64url(new TextEncoder().encode(JSON.stringify(o)));

export async function signJwt(key: CryptoKey, kid: string, claims: Record<string, unknown>): Promise<string> {
  const signing = `${enc({ alg: "RS256", typ: "JWT", kid })}.${enc(claims)}`;
  const sig = await crypto.subtle.sign(RSA_ALG, key, new TextEncoder().encode(signing));
  return `${signing}.${b64url(sig)}`;
}

/** The only signing path. `props` come from ctx.props (deploy-time); `opts` from the consumer. */
export async function issueToken(env: Env, ctx: ExecutionContext, props: unknown, opts: unknown): Promise<TokenResult> {
  const cfg = parseConfig(env);
  const p = validateProps(props);
  const o = validateOpts(opts);
  if (!p.aud.includes(o.aud)) throw new Error("audience not allowed");
  const ttl = Math.min(Math.max(o.ttl ?? cfg.ttl, 60), cfg.ttl);
  const loaded = await loadKeys(env, cfg);
  scheduleTick(env, cfg, ctx, loaded.heal);
  if (!loaded.active) throw new Error("no active signing key");
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;
  const token = await signJwt(loaded.active.key, loaded.active.kid, { iss: cfg.issuer, sub: p.sub, aud: o.aud, iat, nbf: iat, exp, jti: crypto.randomUUID() });
  return { token, expiresAt: exp, kid: loaded.active.kid };
}
