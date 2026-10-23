import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./config.js";
import { issueToken, type Props, type TokenOpts, type TokenResult } from "./jwt.js";

export type { Config, Env, Policy } from "./config.js";
export type { PublicJwk } from "./keys.js";
export type { Props, TokenOpts, TokenResult } from "./jwt.js";
export { KeyRing, type TickReport } from "./keyring.js";
export { default } from "./public.js";

/** RPC entrypoint for consumers. `sub`/`aud` come from deploy-time props; no fetch handler. */
export class Issuer extends WorkerEntrypoint<Env, Props> {
  async getToken(opts: TokenOpts): Promise<TokenResult> {
    return issueToken(this.env, this.ctx, this.ctx.props, opts);
  }
}
