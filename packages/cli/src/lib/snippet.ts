export type SnippetInput = { worker: string; issuerName: string; sub: string; aud: string[] };

/** wrangler.jsonc fragment for the consumer: the `services` binding carries the identity as deploy-time props. */
export function snippetConfig(i: SnippetInput): string {
  return JSON.stringify(
    { name: i.worker, services: [{ binding: "OIDC", service: i.issuerName, entrypoint: "Issuer", props: { sub: i.sub, aud: i.aud } }] },
    null,
    2,
  );
}

/** TypeScript usage example; typechecks against @cloudflare/workers-types (see test/snippet-tsc.test.ts). */
export function snippetCode(i: SnippetInput): string {
  const aud = JSON.stringify(i.aud[0] ?? "");
  return `// src/index.ts of ${i.worker}
interface IssuerApi extends Rpc.WorkerEntrypointBranded {
  getToken(o: { aud: string; ttl?: number }): Promise<{ token: string; expiresAt: number; kid: string }>;
}
interface Env {
  OIDC: Service<IssuerApi>;
}
export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    // sub is fixed to ${JSON.stringify(i.sub)} by the props in wrangler.jsonc; aud must be one of the listed values.
    const { token, expiresAt, kid } = await env.OIDC.getToken({ aud: ${aud} });
    // Exchange \`token\` with your cloud's STS: send it in a POST body only, never in a URL, header log or console.
    return Response.json({ kid, expiresAt, tokenLength: token.length });
  },
} satisfies ExportedHandler<Env>;
`;
}
