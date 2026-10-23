import { beforeEach, expect, it, vi } from "vitest";
import { accessToken, resetCache } from "../src/index";

const ids = {
  ANTHROPIC_ORGANIZATION_ID: "00000000-0000-0000-0000-000000000000",
  ANTHROPIC_FEDERATION_RULE_ID: "fdrl_test",
  ANTHROPIC_SERVICE_ACCOUNT_ID: "svac_test",
  ANTHROPIC_WORKSPACE_ID: "wrkspc_test",
  ANTHROPIC_MODEL: "claude-opus-5-5",
};

function env() {
  let n = 0;
  const getToken = vi.fn(async (_o: { aud: string }) => ({ token: `eyJ.jwt${++n}.sig`, expiresAt: 0, kid: "k" }));
  return { env: { ...ids, OIDC: { getToken } } as never, getToken };
}

beforeEach(() => resetCache());

it("posts a jwt-bearer exchange with the JWT in the body only", async () => {
  const fetchMock = vi.fn(async (_i: RequestInfo | URL, _init?: RequestInit) =>
    Response.json({ access_token: "sk-ant-oat01-x", token_type: "Bearer", expires_in: 600 }),
  );
  vi.stubGlobal("fetch", fetchMock);
  const { env: e, getToken } = env();

  expect(await accessToken(e, 0)).toBe("sk-ant-oat01-x");

  expect(getToken).toHaveBeenCalledWith({ aud: "https://api.anthropic.com" });
  const [url, init] = fetchMock.mock.calls[0]!;
  expect(String(url)).toBe("https://api.anthropic.com/v1/oauth/token");
  expect(String(url)).not.toContain("eyJ");
  expect(init?.method).toBe("POST");
  expect(JSON.parse(String(init?.body))).toEqual({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: "eyJ.jwt1.sig",
    federation_rule_id: "fdrl_test",
    organization_id: "00000000-0000-0000-0000-000000000000",
    service_account_id: "svac_test",
    workspace_id: "wrkspc_test",
  });
});

it("reuses the access token until 60 s before expiry, then exchanges a NEW JWT", async () => {
  const fetchMock = vi.fn(async () => Response.json({ access_token: "t", token_type: "Bearer", expires_in: 600 }));
  vi.stubGlobal("fetch", fetchMock);
  const { env: e, getToken } = env();

  await accessToken(e, 0);
  await accessToken(e, 500_000);
  expect(fetchMock).toHaveBeenCalledTimes(1);

  await accessToken(e, 541_000);
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(getToken).toHaveBeenCalledTimes(2);
  const bodies = fetchMock.mock.calls.map((c) => JSON.parse(String((c as unknown as [unknown, RequestInit])[1].body)).assertion);
  expect(bodies).toEqual(["eyJ.jwt1.sig", "eyJ.jwt2.sig"]);
});

it("fails closed and logs no JWT on a denied exchange", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: { message: "Authentication failed" } }, { status: 401 })));
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const { env: e } = env();

  await expect(accessToken(e, 0)).rejects.toThrow("anthropic exchange failed");
  expect(JSON.stringify(log.mock.calls)).not.toContain("eyJ");
});
