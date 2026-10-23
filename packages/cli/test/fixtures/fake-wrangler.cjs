// Stand-in for wrangler's bin: echoes argv, env and stdin so the spawn helper can be tested.
let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  process.stdout.write(JSON.stringify({ args: process.argv.slice(2), CI: process.env.CI, LOG: process.env.WRANGLER_LOG, M: process.env.WRANGLER_SEND_METRICS, SAN: process.env.WRANGLER_LOG_SANITIZE, WL: process.env.WRANGLER_WRITE_LOGS, CFA: process.env.CLOUDFLARE_ACCOUNT_ID, CFA2: process.env.CF_ACCOUNT_ID, stdinLen: input.length }) + "\n");
  process.stdout.write('{"kty":"RSA","d":"SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRET","n":"x"}\n');
  process.stderr.write("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP\n");
  process.exit(Number(process.argv[2] === "fail" ? 3 : 0));
});
