import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { StringDecoder } from "node:string_decoder";

export type RunOpts = {
  /** one secret value; written to stdin as one line, then stdin ends */
  stdin?: string;
  env?: Record<string, string>;
  onOutput?: (line: string, stream: "stdout" | "stderr") => void;
};

export type RunResult = { code: number; stdout: string; stderr: string };

export function resolveWranglerBin(workerDir: string): string {
  let pkg: string;
  try {
    pkg = createRequire(import.meta.url).resolve("wrangler/package.json", { paths: [workerDir] });
  } catch {
    throw new Error(`wrangler is not installed for ${workerDir}; run \`npm install\` there (or pass --worker-dir)`);
  }
  return join(dirname(pkg), "bin", "wrangler.js");
}

/** Hides private JWK members and token-like strings from streamed output. */
export function redact(line: string): string {
  return line
    .replace(/"(d|p|q|dp|dq|qi)"\s*:\s*"[^"]*"/g, '"$1":"[redacted]"')
    .replace(/Bearer\s+\S+/g, "Bearer [redacted]")
    .replace(/[A-Za-z0-9_-]{40,}/g, "[redacted]");
}

/** Runs `process.execPath <script> ...args` with no shell. Exposed for tests; wrangler goes through runWrangler. */
export function spawnNode(script: string, args: string[], cwd: string, o: RunOpts = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      shell: false,
      // pins come last so neither the operator's shell nor a caller can undo them. WRANGLER_LOG_SANITIZE=false would
      // put request bodies (the JWK, the API token) in wrangler's log; a secret on stdin also turns the disk log off.
      // WRANGLER_LOG is pinned to "log": "debug" puts log lines on stdout around the whoami JSON; "error"/"warn" hide
      // the cli-table3 tables and "Created secret!"; "none" also hides the stderr the error mapper needs (More than one account).
      env: (() => {
        const env: Record<string, string | undefined> = {
          ...process.env,
          ...(o.env ?? {}),
          CI: "1",
          WRANGLER_SEND_METRICS: "false",
          WRANGLER_LOG_SANITIZE: "true",
          WRANGLER_LOG: "log",
          ...(o.stdin !== undefined ? { WRANGLER_WRITE_LOGS: "false" } : {}),
        };
        // account is pinned as account_id in wrangler.jsonc (spec s2); wrangler also honours the deprecated CF_ACCOUNT_ID alias
        delete env["CLOUDFLARE_ACCOUNT_ID"];
        delete env["CF_ACCOUNT_ID"];
        return env;
      })(),
    });
    let stdout = "";
    let stderr = "";
    // a chunk boundary can split a line or a multi-byte char; redact() only sees whole lines, so a token split across
    // two chunks never reaches the screen in halves
    const dec = { stdout: new StringDecoder("utf8"), stderr: new StringDecoder("utf8") };
    const buf = { stdout: "", stderr: "" };
    const emit = (stream: "stdout" | "stderr", s: string) => {
      if (stream === "stdout") stdout += s; else stderr += s;
      if (!o.onOutput) return;
      buf[stream] += s;
      const parts = buf[stream].split(/\r?\n/);
      buf[stream] = parts.pop() ?? "";
      for (const l of parts) if (l) o.onOutput(redact(l), stream);
    };
    const flush = (stream: "stdout" | "stderr") => {
      emit(stream, dec[stream].end());
      if (o.onOutput && buf[stream]) o.onOutput(redact(buf[stream]), stream);
      buf[stream] = "";
    };
    child.stdout.on("data", (c: Buffer) => emit("stdout", dec.stdout.write(c)));
    child.stderr.on("data", (c: Buffer) => emit("stderr", dec.stderr.write(c)));
    child.on("error", reject);
    // close fires after both stdio streams ended, so the flush sees every byte
    child.on("close", (code) => { flush("stdout"); flush("stderr"); resolve({ code: code ?? 1, stdout, stderr }); });
    if (o.stdin !== undefined) child.stdin.write(`${o.stdin}\n`);
    child.stdin.end();
  });
}

/** async so a resolve failure is a rejection, never a sync throw (Home calls this inside useEffect). */
export async function runWrangler(workerDir: string, args: string[], o: RunOpts = {}): Promise<RunResult> {
  return spawnNode(resolveWranglerBin(workerDir), args, workerDir, o);
}
