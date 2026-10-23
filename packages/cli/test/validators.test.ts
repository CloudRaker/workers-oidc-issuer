import { describe, expect, it } from "vitest";
import { intInRange, isIso8601, isWorkerName, validateIssuer, validateKidList } from "../src/lib/validators.js";

describe("validators", () => {
  it("worker name", () => {
    for (const ok of ["oidc-issuer", "a", "a1-b2"]) expect(isWorkerName(ok)).toBe(true);
    for (const bad of ["", "-a", "a-", "A", "a_b", "a".repeat(64)]) expect(isWorkerName(bad)).toBe(false);
  });
  it("ISSUER https origin", () => {
    expect(validateIssuer("https://oidc.example.com")).toBeNull();
    expect(validateIssuer("https://x.acme.workers.dev")).toBeNull();
    expect(validateIssuer("https://oidc.example.com:8443")).toBeNull();
    for (const bad of ["http://oidc.example.com", "https://oidc.example.com/", "https://oidc.example.com/x", "https://oidc.example.com?a=1", "https://oidc.example.com#f", "https://u:p@oidc.example.com", "oidc.example.com", ""]) {
      expect(validateIssuer(bad), bad).not.toBeNull();
    }
  });
  it("ISO-8601", () => {
    expect(isIso8601("2026-10-22T13:00:00Z")).toBe(true);
    expect(isIso8601("2026-10-22T13:00:00.123+02:00")).toBe(true);
    expect(isIso8601("2026-10-22")).toBe(false);
    expect(isIso8601("2026-13-45T13:00:00Z")).toBe(false);
  });
  it("kid list", () => {
    expect(validateKidList("[]")).toBeNull();
    expect(validateKidList('["k1","k2"]')).toBeNull();
    expect(validateKidList('["k1","k1"]')).toMatch(/duplicate/);
    expect(validateKidList('["K1"]')).toMatch(/kid/);
    expect(validateKidList("{}")).toMatch(/array/);
    expect(validateKidList("nope")).toMatch(/array/);
  });
  it("intInRange", () => {
    expect(intInRange("720", 24, 8760)).toBe(720);
    expect(intInRange("10", 24, 8760)).toBeNull();
    expect(intInRange("1e3", 0, 9999)).toBeNull();
  });
});
