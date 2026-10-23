import { Text } from "ink";
import { useEffect } from "react";
import { FlowView, useFlow } from "../flow.js";
import { deploy } from "./ops.js";

export function Deploy(p: { workerDir: string; onDeployed: (targets: string[]) => void }) {
  const { state, run } = useFlow(p.workerDir);
  useEffect(() => {
    void run(async (f) => {
      const targets = await deploy(f);
      p.onDeployed(targets);
      for (const t of targets) f.log(`URL: ${t.startsWith("http") ? t : `https://${t}`}`);
    });
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps
  return <FlowView state={state}><Text bold>Deploy</Text></FlowView>;
}
