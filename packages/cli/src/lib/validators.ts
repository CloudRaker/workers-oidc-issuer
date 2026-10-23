import { isKid } from "./kid.js";

export const WORKER_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export function isWorkerName(s: string): boolean {
  return WORKER_NAME_RE.test(s);
}

/** https origin only: no path, query, hash, credentials, trailing slash. */
export function validateIssuer(s: string): string | null {
  let u: URL;
  try { u = new URL(s); } catch { return "ISSUER must be a URL"; }
  if (u.protocol !== "https:") return "ISSUER must use https";
  if (u.username || u.password) return "ISSUER must not contain credentials";
  if (u.origin !== s) return "ISSUER must be an origin only: no path, query, hash or trailing slash";
  return null;
}

export const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;

export function isIso8601(s: string): boolean {
  return ISO8601_RE.test(s) && !Number.isNaN(Date.parse(s));
}

/** Parses a JSON kid list; returns an error string or null. */
export function validateKidList(s: string): string | null {
  let v: unknown;
  try { v = JSON.parse(s); } catch { return "must be a JSON array"; }
  if (!Array.isArray(v)) return "must be a JSON array";
  if (!v.every((k) => typeof k === "string" && isKid(k))) return "every entry must be a kid matching ^[a-z0-9]{1,32}$";
  if (new Set(v).size !== v.length) return "duplicate kid";
  return null;
}

export function intInRange(s: string, min: number, max: number): number | null {
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return n >= min && n <= max ? n : null;
}
