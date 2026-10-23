import { Box, Text } from "ink";
import { useEffect, useState } from "react";
import { fetchJson } from "../lib/http.js";
import { validateIssuer } from "../lib/validators.js";
import { verifyChecks, verifyPassed, type Check } from "../lib/verify.js";
import { useBackKeys } from "../ui.js";
import { readSummary } from "./ops.js";

export async function runVerify(workerDir: string, targets: string[]): Promise<Check[]> {
  const s = readSummary(workerDir);
  const issuer = s.issuer ?? "";
  const bad = validateIssuer(issuer);
  if (bad) throw new Error(`vars.ISSUER: ${bad}`);
  const [discovery, jwks] = await Promise.all([fetchJson(`${issuer}/.well-known/openid-configuration`), fetchJson(`${issuer}/.well-known/jwks.json`)]);
  return verifyChecks({
    issuer, discovery, jwks,
    ...(s.mode === "manual" ? { expectedKids: s.kids } : {}),
    ...(s.mode === "manual" && s.activeKid ? { activeKid: s.activeKid } : {}),
    ...(targets.length ? { targets } : {}),
  });
}

export function Verify(p: { workerDir: string; targets: string[] }) {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useBackKeys();
  useEffect(() => {
    let live = true;
    runVerify(p.workerDir, p.targets).then((c) => live && setChecks(c)).catch((e: unknown) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => { live = false; };
  }, [p.workerDir, p.targets]);
  return (
    <Box flexDirection="column">
      <Text bold>Verify</Text>
      {error ? <Text color="red">{error}</Text> : null}
      {checks === null && !error ? <Text>fetching discovery + JWKS...</Text> : null}
      {checks?.map((c) => (
        <Text key={c.name}>
          <Text color={c.ok ? "green" : c.warn ? "yellow" : "red"}>{c.ok ? "PASS" : c.warn ? "WARN" : "FAIL"}</Text>  {c.name}  <Text dimColor>{c.detail}</Text>
        </Text>
      ))}
      {checks ? <Text bold color={verifyPassed(checks) ? "green" : "red"}>{verifyPassed(checks) ? "PASS" : "FAIL"}</Text> : null}
      <Text dimColor>esc back, q quit</Text>
    </Box>
  );
}
