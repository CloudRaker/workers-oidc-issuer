import { describe, expect, it } from "vitest";
import { probeOrigin, type Flow } from "../src/screens/ops.js";

const flow = (lines: string[]) => ({ log: (l: string) => lines.push(l) } as unknown as Flow);

describe("probeOrigin", () => {
  it("polls ISSUER when it is a deploy target", () => {
    const lines: string[] = [];
    expect(probeOrigin(flow(lines), "https://oidc.example.com", ["oidc-issuer.acme.workers.dev", "oidc.example.com/*"])).toBe("https://oidc.example.com");
    expect(lines).toEqual([]);
  });
  it("falls back to the workers.dev target and says why when ISSUER is not routed", () => {
    const lines: string[] = [];
    expect(probeOrigin(flow(lines), "https://oidc.example.com", ["https://oidc-issuer.acme.workers.dev"])).toBe("https://oidc-issuer.acme.workers.dev");
    expect(lines[0]).toContain("oidc.example.com is not a deploy target; polling https://oidc-issuer.acme.workers.dev");
  });
  it("keeps ISSUER when there are no targets", () => {
    expect(probeOrigin(flow([]), "https://oidc.example.com", [])).toBe("https://oidc.example.com");
  });
});
