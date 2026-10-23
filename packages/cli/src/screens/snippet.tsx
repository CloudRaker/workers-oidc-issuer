import { Box, Text } from "ink";
import { useEffect, useState } from "react";
import { FlowView, useFlow } from "../flow.js";
import { snippetCode, snippetConfig } from "../lib/snippet.js";
import { isWorkerName } from "../lib/validators.js";
import { readSummary } from "./ops.js";

export function Snippet(p: { workerDir: string }) {
  const { state, run } = useFlow(p.workerDir);
  const [out, setOut] = useState<{ cfg: string; code: string } | null>(null);
  useEffect(() => {
    void run(async (f) => {
      let issuerName = "oidc-issuer";
      try { issuerName = readSummary(p.workerDir).name ?? issuerName; } catch { /* no config: keep the default */ }
      const worker = await f.text("Consumer Worker name", { validate: (s) => (isWorkerName(s) ? null : "lowercase letters, digits and dashes, 1..63 chars") });
      const sub = await f.text("sub (identity asserted at deploy time; printable ASCII, <= 255 chars)", {
        validate: (s) => (s.length >= 1 && s.length <= 255 && /^[\x20-\x7e]+$/.test(s) ? null : "1..255 printable ASCII characters"),
      });
      const audRaw = await f.text("aud allow-list (comma separated, e.g. sts.amazonaws.com)", {
        validate: (s) => (s.split(",").map((x) => x.trim()).filter(Boolean).every((x) => x.length <= 512) && s.trim() ? null : "at least one aud, each <= 512 chars"),
      });
      const aud = audRaw.split(",").map((x) => x.trim()).filter(Boolean);
      setOut({ cfg: snippetConfig({ worker, issuerName, sub, aud }), code: snippetCode({ worker, issuerName, sub, aud }) });
    });
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <FlowView state={state}>
      <Text bold>Consumer snippet</Text>
      {out ? (
        <Box flexDirection="column">
          <Text color="cyan">wrangler.jsonc (services binding with deploy-time props):</Text>
          <Text>{out.cfg}</Text>
          <Text color="cyan">src/index.ts:</Text>
          <Text>{out.code}</Text>
        </Box>
      ) : null}
    </FlowView>
  );
}
