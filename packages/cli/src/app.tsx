import { Box, Text, render, useApp } from "ink";
import { useCallback, useEffect, useMemo, useState } from "react";
import { FlowView, useFlow } from "./flow.js";
import { Deploy } from "./screens/deploy.js";
import { Home, type ScreenName } from "./screens/home.js";
import { Keys } from "./screens/keys.js";
import { pickAccount, whoami } from "./screens/ops.js";
import { Setup } from "./screens/setup.js";
import { Snippet } from "./screens/snippet.js";
import { Verify } from "./screens/verify.js";
import { NavContext } from "./ui.js";

function Account(p: { workerDir: string }) {
  const { state, run } = useFlow(p.workerDir);
  useEffect(() => { void run(async (f) => { await pickAccount(f, (await whoami(f)).accounts); }); }, [run]); // eslint-disable-line react-hooks/exhaustive-deps
  return <FlowView state={state}><Text bold>Change account</Text></FlowView>;
}

export function App(p: { workerDir: string }) {
  const { exit } = useApp();
  const [screen, setScreen] = useState<ScreenName | "home">("home");
  const [targets, setTargets] = useState<string[]>([]);
  const quit = useCallback(() => exit(), [exit]);
  const nav = useMemo(() => ({ back: () => setScreen("home"), quit }), [quit]);
  const go = useCallback((s: ScreenName) => setScreen(s), []);
  return (
    <NavContext.Provider value={nav}>
      <Box flexDirection="column" paddingX={1}>
        {screen === "home" ? <Home workerDir={p.workerDir} onGo={go} onQuit={quit} /> : null}
        {screen === "setup" ? <Setup workerDir={p.workerDir} onDeployed={setTargets} onDone={() => setScreen("verify")} /> : null}
        {screen === "keys" ? <Keys workerDir={p.workerDir} /> : null}
        {screen === "deploy" ? <Deploy workerDir={p.workerDir} onDeployed={setTargets} /> : null}
        {screen === "snippet" ? <Snippet workerDir={p.workerDir} /> : null}
        {screen === "verify" ? <Verify workerDir={p.workerDir} targets={targets} /> : null}
        {screen === "account" ? <Account workerDir={p.workerDir} /> : null}
      </Box>
    </NavContext.Provider>
  );
}

export function run(workerDir: string): void {
  render(<App workerDir={workerDir} />);
}
