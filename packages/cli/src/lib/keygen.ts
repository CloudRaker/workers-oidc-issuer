import { webcrypto } from "node:crypto";

export const PRIVATE_JWK_MEMBERS = ["alg", "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"] as const;
const B64URL = /^[A-Za-z0-9_-]+$/;

export type PrivateJwk = {
  kty: "RSA"; alg: "RS256"; use: "sig"; kid: string;
  n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string;
};

export async function generatePrivateJwk(kid: string): Promise<PrivateJwk> {
  const pair = await webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const raw = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  const pick = (k: string): string => {
    const v = (raw as Record<string, unknown>)[k];
    if (typeof v !== "string" || !B64URL.test(v)) throw new Error(`exported JWK missing member ${k}`);
    return v;
  };
  // Allow-list build: never spread the exported object (key_ops, ext would leak in).
  return {
    kty: "RSA", alg: "RS256", use: "sig", kid,
    n: pick("n"), e: pick("e"), d: pick("d"), p: pick("p"), q: pick("q"), dp: pick("dp"), dq: pick("dq"), qi: pick("qi"),
  };
}

/** Structural check mirroring the worker's rule: exact member set, RSA/RS256/sig, base64url bigs. */
export function isPrivateJwk(x: unknown): x is PrivateJwk {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== PRIVATE_JWK_MEMBERS.length || keys.some((k, i) => k !== PRIVATE_JWK_MEMBERS[i])) return false;
  if (o["kty"] !== "RSA" || o["alg"] !== "RS256" || o["use"] !== "sig") return false;
  for (const k of ["n", "e", "d", "p", "q", "dp", "dq", "qi"]) {
    if (typeof o[k] !== "string" || !B64URL.test(o[k] as string)) return false;
  }
  return typeof o["kid"] === "string";
}
