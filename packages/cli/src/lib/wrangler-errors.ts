import { redact } from "./wrangler.js";

export type Mapped = { kind: string; message: string; raw: string };

const RULES: [kind: string, re: RegExp, cmd: RegExp | null, message: string][] = [
  ["multi-account", /More than one account/i, null, "Your login reaches more than one account. Pick one; the CLI pins it as account_id in wrangler.jsonc."],
  ["login", /not authenticated|no credentials were found|auth token has expired|"loggedIn"\s*:\s*false/i, null, "Not logged in. Run `wrangler login` in a terminal, then retry."],
  ["secret-exists", /already exists/i, /secrets-store secret create/, "A Secrets Store secret with this name already exists. Re-run Setup (it updates OIDC_CF_API_TOKEN in place and reuses OIDC_KEYSET), or remove it: `wrangler secrets-store secret delete <store-id> --secret-id <id> --remote`."],
  ["secrets-store-role", /authorization|forbidden|\b403\b|\[code: 100\d\]/i, /secrets-store (store|secret) create/, "Your role cannot create Secrets Store entries. You need Super Administrator or Secrets Store Admin on this account. Re-run `wrangler login` after the role changes."],
  ["deploy-secrets-role", /failed to fetch secrets store binding due to authorization error/i, null, "Deploying with Secrets Store bindings needs the Deployer role plus Secrets Store Edit (API token: Workers Scripts Edit + Secrets Store Edit)."],
  ["secret-limit", /(limit|quota|maximum).{0,40}secrets|100 secrets/i, null, "This account has reached the Secrets Store limit (100 secrets per account). Remove retired OIDC_KEY_* secrets first."],
  ["workers-dev", /register a workers\.dev subdomain/i, null, "This account has no workers.dev subdomain yet. Register one at https://dash.cloudflare.com/?to=/:account/workers/onboarding and retry."],
];

/** Maps wrangler stderr/stdout to an operator hint. Raw text is always kept, redacted, for display under the hint. */
export function mapWranglerError(command: string, output: string): Mapped {
  const raw = redact(output); // ponytail: one sink for everything that reaches the screen; rules match the untouched text
  for (const [kind, re, cmd, message] of RULES) {
    if (re.test(output) && (cmd === null || cmd.test(command))) return { kind, message, raw };
  }
  return { kind: "unknown", message: `${command} failed`, raw };
}
