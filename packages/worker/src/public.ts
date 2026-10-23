import { ConfigError, type Env, parseConfig } from "./config.js";
import { keyring, loadKeys, scheduleTick } from "./keys.js";

/** Public surface. This module never imports jwt.ts: the fetch path cannot sign (static test). */
const DISCOVERY = "/.well-known/openid-configuration";
const JWKS = "/.well-known/jwks.json";

function respond(status: number, body: unknown, head: boolean, extra: Record<string, string> = {}): Response {
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=31536000",
    "cache-control": status === 200 ? "public, max-age=3600" : "no-store",
    ...extra,
  };
  return new Response(head ? null : JSON.stringify(body), { status, headers });
}

export default {
  async fetch(req, env, ctx) {
    const path = new URL(req.url).pathname;
    const head = req.method === "HEAD";
    if (path !== DISCOVERY && path !== JWKS) return respond(404, { error: "not_found" }, head);
    if (req.method !== "GET" && !head) return respond(405, { error: "method_not_allowed" }, false, { allow: "GET, HEAD" });
    let cfg;
    try {
      cfg = parseConfig(env);
    } catch (e) {
      console.warn(e instanceof ConfigError ? e.message : "misconfigured");
      return respond(500, { error: "misconfigured" }, head);
    }
    if (path === DISCOVERY) {
      return respond(200, {
        issuer: cfg.issuer,
        jwks_uri: `${cfg.issuer}/.well-known/jwks.json`,
        response_types_supported: ["id_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        claims_supported: ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"],
        scopes_supported: ["openid"],
      }, head);
    }
    let loaded;
    try {
      loaded = await loadKeys(env, cfg);
    } catch {
      // DO RPC / storage failure: 500 no-store so nothing caches an empty or missing JWKS. No tick: the DO is already failing.
      console.warn("keys unavailable");
      return respond(500, { error: "unavailable" }, head);
    }
    scheduleTick(env, cfg, ctx, loaded.heal);
    // No usable active key (bootstrap, heal window, broken active slot): 200 so pollers see the shape, but never cacheable.
    return respond(200, { keys: loaded.published }, head, loaded.active ? {} : { "cache-control": "no-store" });
  },

  async scheduled(_controller, env, _ctx) {
    let cfg;
    try {
      cfg = parseConfig(env);
    } catch (e) {
      console.warn(e instanceof ConfigError ? e.message : "misconfigured");
      return;
    }
    if (cfg.mode === "auto") await keyring(env).tick(cfg.policy);
  },
} satisfies ExportedHandler<Env>;
