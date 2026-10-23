import { randomBytes } from "node:crypto";

export const KID_RE = /^[a-z0-9]{1,32}$/;

export function isKid(s: string): boolean {
  return KID_RE.test(s);
}

/** Manual-mode kid: k + yyyymmdd + 4 random hex. */
export function newManualKid(now: Date = new Date()): string {
  const d = now.toISOString().slice(0, 10).replace(/-/g, "");
  return `k${d}${randomBytes(2).toString("hex")}`;
}

/** Auto-mode kid: k + unix seconds + 4 random hex. */
export function newAutoKid(now: Date = new Date()): string {
  return `k${Math.floor(now.getTime() / 1000)}${randomBytes(2).toString("hex")}`;
}

/** Creation time derived from the kid, or null when the kid carries no timestamp. */
export function kidCreatedAt(kid: string): Date | null {
  const m = /^k(\d{8}|\d{10})[0-9a-f]{4}$/.exec(kid);
  if (!m) return null;
  const ts = m[1] as string;
  if (ts.length === 10) return new Date(Number(ts) * 1000);
  const d = new Date(`${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function assertNewKid(kid: string, existing: readonly string[]): void {
  if (!isKid(kid)) throw new Error(`invalid kid "${kid}": must match ${KID_RE}`);
  if (existing.includes(kid)) throw new Error(`kid "${kid}" already has a binding`);
}
