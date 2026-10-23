import { isJwks } from "./jwks.js";

export type Check = { name: string; ok: boolean; detail: string; warn?: boolean };

export type VerifyInput = {
  issuer: string;
  discovery: unknown;
  jwks: unknown;
  /** manual mode: kids that must appear; undefined for auto mode */
  expectedKids?: string[];
  activeKid?: string;
  /** last deploy targets, when known: ISSUER should be among them (warn only) */
  targets?: string[];
};

export function verifyChecks(i: VerifyInput): Check[] {
  const out: Check[] = [];
  const d = (typeof i.discovery === "object" && i.discovery !== null ? i.discovery : {}) as Record<string, unknown>;
  const jwksUri = `${i.issuer}/.well-known/jwks.json`;
  out.push({ name: "discovery.issuer", ok: d["issuer"] === i.issuer, detail: `${String(d["issuer"])} == ${i.issuer}` });
  out.push({ name: "discovery.jwks_uri", ok: d["jwks_uri"] === jwksUri, detail: `${String(d["jwks_uri"])} == ${jwksUri}` });
  const algs = d["id_token_signing_alg_values_supported"];
  out.push({ name: "discovery.alg", ok: Array.isArray(algs) && algs.length === 1 && algs[0] === "RS256", detail: JSON.stringify(algs) });
  const jwks = i.jwks;
  const shape = isJwks(jwks);
  out.push({ name: "jwks.shape", ok: shape, detail: shape ? `${jwks.keys.length} key(s)` : "not a JWKS" });
  if (!shape) return out;
  const kids = jwks.keys.map((k) => k.kid);
  out.push({ name: "jwks.nonEmpty", ok: kids.length >= 1, detail: kids.join(", ") || "(empty)" });
  out.push({ name: "jwks.rs256", ok: jwks.keys.every((k) => k.kty === "RSA" && k.alg === "RS256" && k.use === "sig"), detail: "kty RSA, alg RS256, use sig" });
  if (i.expectedKids) {
    const missing = i.expectedKids.filter((k) => !kids.includes(k));
    out.push({ name: "jwks.bindings", ok: missing.length === 0, detail: missing.length ? `missing ${missing.join(", ")}` : "every binding kid published" });
  }
  if (i.activeKid !== undefined) {
    out.push({ name: "jwks.active", ok: kids[0] === i.activeKid, detail: `first key ${String(kids[0])} == ACTIVE_KID ${i.activeKid}` });
  }
  if (i.targets) {
    const host = new URL(i.issuer).host;
    const norm = (t: string) => t.replace(/^https?:\/\//, "").replace(/\/\*?$/, "");
    const hit = i.targets.some((t) => norm(t) === host);
    out.push({ name: "deploy.target", ok: hit, warn: true, detail: hit ? "ISSUER is a deploy target" : `ISSUER not among last deploy targets (${i.targets.join(", ") || "none"})` });
  }
  return out;
}

export function verifyPassed(checks: Check[]): boolean {
  return checks.every((c) => c.ok || c.warn);
}
