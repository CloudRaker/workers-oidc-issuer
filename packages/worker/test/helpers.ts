import { adminSecretsStore, createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { expect, vi } from "vitest";
import type { Env, Issuer, KeyRing } from "../src/index";
import worker from "../src/index";

export type TestEnv = Env & {
  AS_CONSUMER_A: Service<Issuer>;
  CF_API: Fetcher;
  KEYRING: DurableObjectNamespace<KeyRing>;
  OIDC_KEYSET: SecretsStoreSecret;
  CF_API_TOKEN: SecretsStoreSecret;
  OIDC_KEY_k0: SecretsStoreSecret;
  OIDC_KEY_k1: SecretsStoreSecret;
  OIDC_KEY_k2: SecretsStoreSecret;
};
export const E = env as unknown as TestEnv;
export const ISSUER = "https://oidc.example.com";
export const MEMBERS = ["alg", "d", "dp", "dq", "e", "kid", "kty", "n", "p", "q", "qi", "use"];

export async function genJwk(kid: string, modulusLength = 2048): Promise<Record<string, unknown>> {
  const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = (await crypto.subtle.exportKey("jwk", kp.privateKey)) as unknown as Record<string, unknown>;
  return { ...Object.fromEntries(MEMBERS.map((m) => [m, raw[m]])), kid, alg: "RS256", use: "sig", kty: "RSA" };
}

/** Seeds a Secrets Store binding (isolated storage: per test). */
export async function seed(binding: SecretsStoreSecret, value: string): Promise<string> {
  using admin = adminSecretsStore(binding);
  return admin.create(value);
}

/** A valid manual-mode env with k0 seeded and only the listed OIDC_KEY_ bindings; vars can be overridden. */
export async function manualEnv(over: Partial<Record<keyof Env, unknown>> = {}, kids: string[] = ["k0"]): Promise<TestEnv> {
  await seed(E.OIDC_KEY_k0, JSON.stringify(await genJwk("k0")));
  return onlyKids({ ...E, ISSUER, ROTATION: "manual", ACTIVE_KID: "k0", TOKEN_TTL_SECONDS: "300", ...over } as TestEnv, kids);
}

/** A valid auto-mode env (no OIDC_KEY_ bindings); vars can be overridden, `undefined` drops a binding. */
export function autoEnv(over: Partial<Record<keyof Env, unknown>> = {}): TestEnv {
  const base = Object.fromEntries(Object.entries(E).filter(([k]) => !k.startsWith("OIDC_KEY_")));
  return { ...base, ISSUER, ROTATION: "auto", TOKEN_TTL_SECONDS: "300", ROTATION_INTERVAL_HOURS: "720", ROTATION_GRACE_HOURS: "24", ROTATE_NONCE: "", REVOKE_BEFORE: "", RETIRE_KIDS: "[]", ...over } as unknown as TestEnv;
}

/** Every private member value of the given JWKs; pass to spyConsole()/done() so a bare leaked value fails the test. */
export const privates = (jwks: Record<string, unknown>[]): string[] => jwks.flatMap((k) => ["d", "p", "q", "dp", "dq", "qi"].map((m) => k[m] as string));

/** Env with only the listed OIDC_KEY_ bindings. */
export function onlyKids(e: TestEnv, kids: string[]): TestEnv {
  const out = Object.fromEntries(Object.entries(e).filter(([k]) => !k.startsWith("OIDC_KEY_") || kids.includes(k.slice(9))));
  return out as TestEnv;
}

export async function get(e: TestEnv, path: string, init?: RequestInit): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ISSUER}${path}`, init) as Request<unknown, IncomingRequestCfProperties>, e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

/**
 * Console spy. `forbidden` (here or on `done`) are secret or config values that must not appear in any output.
 * Assert on `warn` before `done()`: `done()` restores the spies and returns the captured output.
 */
export function spyConsole(forbidden: string[] = []) {
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  const spies = [warn, ...(["log", "error", "info", "debug"] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}))];
  return {
    warn,
    done(extra: string[] = []): string {
      const out = spies.flatMap((s) => s.mock.calls.flat()).map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join("\n");
      for (const s of spies) s.mockRestore();
      expect(out).not.toMatch(/"d":|"p":|"q":|"dp":|"dq":|"qi":|eyJ|test-api-token/);
      for (const f of [...forbidden, ...extra]) expect(out).not.toContain(f);
      return out;
    },
  };
}
