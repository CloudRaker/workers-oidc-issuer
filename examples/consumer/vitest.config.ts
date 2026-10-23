import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

// No wrangler.jsonc here: the OIDC service binding points at a Worker that is
// not part of this test. The one test stubs fetch and never calls the binding.
export default defineConfig({
  plugins: [cloudflareTest({ miniflare: { compatibilityDate: "2026-10-13" } })],
});
