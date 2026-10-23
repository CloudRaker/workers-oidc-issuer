import { beforeEach, expect, it, vi } from "vitest";
import { accessToken, resetCache } from "../src/index";

const ids = { OPENAI_IDENTITY_PROVIDER_ID: "idp_test", OPENAI_SERVICE_ACCOUNT_ID: "svc_test" };

function env() {
  let n = 0;
  const getToken = vi.fn(async (_o: { aud: string }) => ({ token: `eyJ.jwt${++n}.sig`, expiresAt: 0, kid: "k" }));
  return { env: { ...ids, OIDC: { getToken } } as never, getToken };
}

beforeEach(() => resetCache());

it("posts an RFC 8693 token exchange with the JWT in the body only", async () => {
  const fetchMock = vi.fn(async (_i: RequestInfo | URL, _init?: RequestInit) =>
    Response.json({ access_token: "oa-x", token_type: "Bearer", expires_in: 3600, expires_at: 3600 }),
  );
  vi.stubGlobal("fetch", fetchMock);
  const { env: e, getToken } = env();

  expect(await accessToken(e, 0)).toBe("oa-x");

  expect(getToken).toHaveBeenCalledWith({ aud: "https://api.openai.com" });
  const [url, init] = fetchMock.mock.calls[0]!;
  expect(String(url)).toBe("https://auth.openai.com/oauth/token");
  expect(String(url)).not.toContain("eyJ");
  expect(init?.method).toBe("POST");
  expect(JSON.parse(String(init?.body))).toEqual({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    subject_token: "eyJ.jwt1.sig",
    identity_provider_id: "idp_test",
    service_account_id: "svc_test",
  });
});

it("caches until 60 s before expires_at, then exchanges a new JWT", async () => {
  const fetchMock = vi.fn(async () => Response.json({ access_token: "t", token_type: "Bearer", expires_in: 3600, expires_at: 3600 }));
  vi.stubGlobal("fetch", fetchMock);
  const { env: e, getToken } = env();

  await accessToken(e, 0);
  await accessToken(e, 3_500_000);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await accessToken(e, 3_541_000);
  expect(getToken).toHaveBeenCalledTimes(2);
});

it("fails closed and logs no JWT on a denied exchange", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "invalid_grant" }, { status: 400 })));
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const { env: e } = env();

  await expect(accessToken(e, 0)).rejects.toThrow("openai exchange failed");
  expect(JSON.stringify(log.mock.calls)).not.toContain("eyJ");
});
