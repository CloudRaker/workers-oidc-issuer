import { describe, expect, it } from "vitest";
import { PRIVATE_JWK_MEMBERS, generatePrivateJwk, isPrivateJwk } from "../src/lib/keygen.js";

describe("keygen", () => {
  it("produces the exact private JWK member set", async () => {
    const jwk = await generatePrivateJwk("k20261022abcd");
    expect(Object.keys(jwk).sort()).toEqual([...PRIVATE_JWK_MEMBERS]);
    expect(jwk).toMatchObject({ kty: "RSA", alg: "RS256", use: "sig", kid: "k20261022abcd", e: "AQAB" });
    expect(isPrivateJwk(jwk)).toBe(true);
    // 2048-bit modulus: 256 bytes -> 342 base64url chars
    expect(jwk.n).toHaveLength(342);
  }, 20_000);
  it("rejects extra or missing members", async () => {
    const jwk = await generatePrivateJwk("k0");
    expect(isPrivateJwk({ ...jwk, key_ops: ["sign"] })).toBe(false);
    expect(isPrivateJwk({ ...jwk, ext: true })).toBe(false);
    const { qi: _qi, ...missing } = jwk;
    expect(isPrivateJwk(missing)).toBe(false);
    expect(isPrivateJwk({ ...jwk, alg: "RS512" })).toBe(false);
  }, 20_000);
});
