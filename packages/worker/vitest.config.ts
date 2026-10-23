import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export const STORE = "fedcba9876543210fedcba9876543210";
export const ACCOUNT = "0123456789abcdef0123456789abcdef";

// Tiny fake of the Secrets Store REST API. Runs in Node; the KeyRing reaches it through the CF_API service binding.
let captured: string | null = null;
let fail = false;
let hang = false;
async function fakeCfApi(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/__captured") return new Response(captured ?? "", { status: captured === null ? 404 : 200 });
  if (url.pathname === "/__fail") { fail = (await req.text()) === "on"; return new Response("ok"); }
  if (url.pathname === "/__hang") { hang = (await req.text()) === "on"; return new Response("ok"); }
  if (url.pathname === "/__reset") { captured = null; fail = false; hang = false; return new Response("ok"); }
  if (req.headers.get("authorization") !== "Bearer test-api-token") return Response.json({ success: false }, { status: 403 });
  const secrets = `/client/v4/accounts/${ACCOUNT}/secrets_store/stores/${STORE}/secrets`;
  if (req.method === "GET" && url.pathname === secrets) {
    if (url.searchParams.get("search") !== "OIDC_KEYSET" || url.searchParams.get("per_page") !== "100") return Response.json({ success: false }, { status: 400 });
    // Decoy first: a prefix/includes match resolves sec2, whose PATCH 404s.
    return Response.json({ success: true, result: [{ id: "sec2", name: "OIDC_KEYSET_OLD" }, { id: "sec1", name: "OIDC_KEYSET" }] });
  }
  if (req.method === "PATCH" && url.pathname === `${secrets}/sec1`) {
    if (fail) return Response.json({ success: false }, { status: 500 });
    if (hang) return new Promise(() => {});
    captured = ((await req.json()) as { value: string }).value;
    return Response.json({ success: true, result: { id: "sec1" } });
  }
  return new Response("not found", { status: 404 });
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      // test/wrangler.jsonc: the shipped config minus disable_ctx_exports (see the comment there) plus the test bindings.
      wrangler: { configPath: "./test/wrangler.jsonc" },
      miniflare: {
        serviceBindings: {
          AS_CONSUMER_A: { name: "oidc-issuer", entrypoint: "Issuer", props: { sub: "consumer-a", aud: ["sts.amazonaws.com", "https://vault.example"] } },
          CF_API: fakeCfApi,
        },
      },
    }),
  ],
});
