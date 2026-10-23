import { describe, expect, it } from "vitest";
import { KID_RE, assertNewKid, isKid, kidCreatedAt, newAutoKid, newManualKid } from "../src/lib/kid.js";

describe("kid", () => {
  it("manual kid = k + yyyymmdd + 4 hex", () => {
    const k = newManualKid(new Date("2026-10-22T13:00:00Z"));
    expect(k).toMatch(/^k20261022[0-9a-f]{4}$/);
    expect(KID_RE.test(k)).toBe(true);
    expect(kidCreatedAt(k)?.toISOString()).toBe("2026-10-22T00:00:00.000Z");
  });
  it("auto kid = k + unix seconds + 4 hex", () => {
    const k = newAutoKid(new Date(1_761_138_000_000));
    expect(k).toMatch(/^k1761138000[0-9a-f]{4}$/);
    expect(kidCreatedAt(k)?.getTime()).toBe(1_761_138_000_000);
    expect(kidCreatedAt("k0")).toBeNull();
  });
  it("regex", () => {
    for (const bad of ["", "K1", "k-1", "a".repeat(33), "k 1"]) expect(isKid(bad)).toBe(false);
    for (const ok of ["k0", "a".repeat(32), "k20261022abcd"]) expect(isKid(ok)).toBe(true);
  });
  it("duplicate check", () => {
    expect(() => assertNewKid("k1", ["k0"])).not.toThrow();
    expect(() => assertNewKid("k0", ["k0"])).toThrow(/already/);
    expect(() => assertNewKid("K0", [])).toThrow(/invalid kid/);
  });
});
