import { Box, Text } from "ink";
import { useCallback, useMemo, useRef, useState } from "react";
import { mapWranglerError } from "./lib/wrangler-errors.js";
import { runWrangler, type RunOpts, type RunResult } from "./lib/wrangler.js";
import { Cancelled, WranglerError, pickAccount, whoami, type Flow } from "./screens/ops.js";
import { Confirm, ErrorView, Menu, OutputBox, TextInput, useBackKeys, type MenuItem } from "./ui.js";

type Prompt =
  | { kind: "menu"; title: string; items: MenuItem[]; resolve: (v: string) => void; reject: (e: Error) => void }
  | { kind: "text"; label: string; mask: boolean; validate?: (s: string) => string | null; resolve: (v: string) => void; reject: (e: Error) => void }
  | { kind: "confirm"; text: string; resolve: (ok: boolean) => void; reject: (e: Error) => void };

export type FlowStatus = "idle" | "running" | "done" | "cancelled" | "error";
export type FlowState = { status: FlowStatus; lines: string[]; error: Error | null; prompt: Prompt | null };

/** Sequential async flows (prompt, log, wrangler) rendered by FlowView. */
export function useFlow(workerDir: string) {
  const [state, setState] = useState<FlowState>({ status: "idle", lines: [], error: null, prompt: null });
  const log = useCallback((line: string) => setState((s) => ({ ...s, lines: [...s.lines, line] })), []);
  const ask = useCallback(<T,>(make: (resolve: (v: T) => void, reject: (e: Error) => void) => Prompt) =>
    new Promise<T>((resolve, reject) => setState((s) => ({ ...s, prompt: make((v) => { setState((x) => ({ ...x, prompt: null })); resolve(v); }, (e) => { setState((x) => ({ ...x, prompt: null })); reject(e); }) }))), []);
  const flow = useMemo<Flow>(() => {
    const f: Flow = {
      workerDir,
      log,
      menu: (title, items) => ask<string>((resolve, reject) => ({ kind: "menu", title, items, resolve, reject })),
      text: (label, o) => ask<string>((resolve, reject) => ({ kind: "text", label, mask: o?.mask ?? false, ...(o?.validate ? { validate: o.validate } : {}), resolve, reject })),
      confirm: (text) => ask<boolean>((resolve, reject) => ({ kind: "confirm", text, resolve, reject })),
      async wrangler(args, o) {
        const { allowFail, ...rest } = o ?? {};
        const run = async (): Promise<RunResult> => {
          log(`$ wrangler ${args.join(" ")}`);
          const opts: RunOpts = { ...rest, onOutput: (l) => log(l) };
          return runWrangler(workerDir, args, opts);
        };
        let r = await run();
        const cmd = `wrangler ${args.join(" ")}`;
        if (r.code !== 0 && !allowFail) {
          // stderr last: ErrorView shows the tail of the raw text and wrangler writes its error to stderr
          let m = mapWranglerError(cmd, `${r.stdout}\n${r.stderr}`);
          if (m.kind === "multi-account") {
            await pickAccount(f, (await whoami(f)).accounts);
            r = await run();
            if (r.code === 0) return r;
            m = mapWranglerError(cmd, `${r.stdout}\n${r.stderr}`);
          }
          throw new WranglerError(m);
        }
        return r;
      },
    };
    return f;
  }, [workerDir, log, ask]);
  const running = useRef(false);
  const run = useCallback(async (fn: (f: Flow) => Promise<void>): Promise<FlowStatus> => {
    if (running.current) return "running";
    running.current = true;
    setState((s) => ({ ...s, status: "running", error: null }));
    let status: FlowStatus;
    let error: Error | null = null;
    try { await fn(flow); status = "done"; } catch (e) {
      if (e instanceof Cancelled) status = "cancelled";
      else { status = "error"; error = e instanceof Error ? e : new Error(String(e)); }
    }
    running.current = false;
    setState((s) => ({ ...s, status, error, prompt: null }));
    return status;
  }, [flow]);
  const reset = useCallback(() => setState({ status: "idle", lines: [], error: null, prompt: null }), []);
  return { state, run, log, reset };
}

export function FlowView(p: { state: FlowState; children?: React.ReactNode }) {
  const { status, lines, error, prompt } = p.state;
  const cancel = (reject: (e: Error) => void) => () => reject(new Cancelled());
  useBackKeys(status !== "running");
  return (
    <Box flexDirection="column">
      <OutputBox lines={lines} active={prompt === null} />
      {p.children}
      {prompt?.kind === "menu" ? <Menu title={prompt.title} items={prompt.items} onSelect={prompt.resolve} onCancel={cancel(prompt.reject)} /> : null}
      {prompt?.kind === "text" ? <TextInput label={prompt.label} mask={prompt.mask} {...(prompt.validate ? { validate: prompt.validate } : {})} onSubmit={prompt.resolve} onCancel={cancel(prompt.reject)} /> : null}
      {prompt?.kind === "confirm" ? <Confirm text={prompt.text} onAnswer={prompt.resolve} /> : null}
      {status === "running" && prompt === null ? <Text color="yellow">working... (esc is ignored while a step runs)</Text> : null}
      {status === "error" && error ? <ErrorView message={error.message} {...(error instanceof WranglerError ? { raw: error.mapped.raw } : {})} /> : null}
      {status === "done" || status === "error" || status === "cancelled" ? <Text dimColor>esc back, q quit</Text> : null}
    </Box>
  );
}
