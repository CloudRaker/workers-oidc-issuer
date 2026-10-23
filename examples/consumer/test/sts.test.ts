import { expect, it, vi } from "vitest";
import { assumeRole } from "../src/index";

it("sends the token in the POST body, never in the URL", async () => {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
    Response.json({
      AssumeRoleWithWebIdentityResponse: {
        AssumeRoleWithWebIdentityResult: {
          Credentials: {
            AccessKeyId: "ASIAEXAMPLE",
            SecretAccessKey: "x",
            SessionToken: "y",
            Expiration: "2099-01-01T00:00:00Z",
          },
        },
      },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  const creds = await assumeRole("eyJ.fake.token", {
    AWS_REGION: "us-east-1",
    AWS_ROLE_ARN: "arn:aws:iam::123456789012:role/example-consumer",
  });

  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0]!;
  expect(String(url)).toBe("https://sts.us-east-1.amazonaws.com/");
  expect(String(url)).not.toContain("WebIdentityToken");
  expect(String(url)).not.toContain("eyJ");
  expect(init?.method).toBe("POST");
  expect(String(init?.body)).toContain("WebIdentityToken=eyJ.fake.token");
  expect(creds.AccessKeyId).toBe("ASIAEXAMPLE");
});
