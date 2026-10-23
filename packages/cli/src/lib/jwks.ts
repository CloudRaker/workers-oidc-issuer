import { createHash } from "node:crypto";
import { kidCreatedAt } from "./kid.js";

export type PublicJwk = { kty: string; n: string; e: string; kid: string; alg?: string; use?: string };
export type Jwks = { keys: PublicJwk[] };

export function isJwks(x: unknown): x is Jwks {
  if (typeof x !== "object" || x === null || !Array.isArray((x as { keys?: unknown }).keys)) return false;
  return (x as Jwks).keys.every((k) => typeof k === "object" && k !== null && typeof k.kid === "string" && typeof k.n === "string" && typeof k.e === "string");
}

export function fingerprint(k: Pick<PublicJwk, "n" | "e">): string {
  return createHash("sha256").update(`${k.n}.${k.e}`).digest("base64url");
}

export function formatAge(ms: number): string {
  const m = Math.max(0, Math.floor(ms / 60_000));
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

export type JwksRow = { kid: string; fp: string; age: string; role: "active" | "next" | "retiring" | "published" };

/** Rows for the Keys screen and `keys list --json`. First key is active; the rest are next (newer than active) or retiring (older). */
export function buildJwksTable(jwks: Jwks, now: number = Date.now()): JwksRow[] {
  const act = kidCreatedAt(jwks.keys[0]?.kid ?? "")?.getTime();
  return jwks.keys.map((k, i) => {
    const created = kidCreatedAt(k.kid);
    // >= not >: a retiring key is always strictly older than active; a same-second non-active key is a real `next` (emergency-revoke edge)
    const role: JwksRow["role"] = i === 0 ? "active" : created && act !== undefined ? (created.getTime() >= act ? "next" : "retiring") : "published";
    return { kid: k.kid, fp: fingerprint(k), age: created ? formatAge(now - created.getTime()) : "?", role };
  });
}
