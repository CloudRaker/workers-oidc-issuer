import { Box, Text, useInput } from "ink";
import { createContext, useContext, useState } from "react";

export type Nav = { back: () => void; quit: () => void };
export const NavContext = createContext<Nav>({ back: () => {}, quit: () => {} });
export const useNav = (): Nav => useContext(NavContext);

/** Esc -> back, q -> quit. For views that own no other input. */
export function useBackKeys(active = true): void {
  const nav = useNav();
  useInput((input, key) => {
    if (key.escape) nav.back();
    else if (input === "q") nav.quit();
  }, { isActive: active });
}

export type MenuItem = { label: string; value: string; hint?: string };

export function Menu(p: { title: string; items: MenuItem[]; onSelect: (v: string) => void; onCancel: () => void }) {
  const nav = useNav();
  const [i, setI] = useState(0);
  const n = p.items.length;
  useInput((input, key) => {
    if (key.upArrow) setI((x) => (x + n - 1) % n);
    else if (key.downArrow) setI((x) => (x + 1) % n);
    else if (key.return) { const it = p.items[i]; if (it) p.onSelect(it.value); }
    else if (key.escape) p.onCancel();
    else if (input === "q") nav.quit();
  });
  return (
    <Box flexDirection="column">
      <Text bold>{p.title}</Text>
      {p.items.map((it, k) => (
        <Text key={it.value} {...(k === i ? { color: "cyan" } : {})}>
          {k === i ? "> " : "  "}{it.label}{it.hint ? <Text dimColor>  {it.hint}</Text> : null}
        </Text>
      ))}
      <Text dimColor>arrows move, enter selects, esc back, q quit</Text>
    </Box>
  );
}

export function TextInput(p: { label: string; mask?: boolean; validate?: (s: string) => string | null; onSubmit: (v: string) => void; onCancel: () => void }) {
  const [v, setV] = useState("");
  const [err, setErr] = useState<string | null>(null);
  useInput((input, key) => {
    if (key.escape) { setV(""); p.onCancel(); return; }
    if (key.return) {
      const e = p.validate ? p.validate(v) : null;
      if (e) { setErr(e); return; }
      setV(""); // drop the buffer before handing the value on
      p.onSubmit(v);
      return;
    }
    if (key.backspace || key.delete) { setV((s) => s.slice(0, -1)); setErr(null); return; }
    if (key.ctrl || key.meta || key.tab || key.upArrow || key.downArrow || key.leftArrow || key.rightArrow) return;
    if (input) { setV((s) => s + input); setErr(null); }
  });
  return (
    <Box flexDirection="column">
      <Text>{p.label}</Text>
      <Text>{"> "}{p.mask ? "*".repeat(v.length) : v}<Text inverse> </Text></Text>
      {err ? <Text color="red">{err}</Text> : <Text dimColor>enter submits, esc cancels</Text>}
    </Box>
  );
}

export function Confirm(p: { text: string; onAnswer: (ok: boolean) => void }) {
  useInput((input, key) => {
    if (input === "y" || input === "Y") p.onAnswer(true);
    else if (input === "n" || input === "N" || key.escape) p.onAnswer(false);
  });
  return <Text>{p.text} <Text dimColor>[y/N]</Text></Text>;
}

/** Last `height` lines, scrollable with arrows (PageUp/PageDown jump). */
export function OutputBox(p: { lines: string[]; height?: number; active?: boolean }) {
  const h = p.height ?? 12;
  const [off, setOff] = useState(0);
  const max = Math.max(0, p.lines.length - h);
  const o = Math.min(off, max);
  useInput((_input, key) => {
    if (key.upArrow || key.pageUp) setOff(Math.min(max, o + (key.pageUp ? h : 1)));
    else if (key.downArrow || key.pageDown) setOff(Math.max(0, o - (key.pageDown ? h : 1)));
  }, { isActive: p.active ?? true });
  if (p.lines.length === 0) return null;
  const end = p.lines.length - o;
  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
      {p.lines.slice(Math.max(0, end - h), end).map((l, i) => <Text key={i}>{l}</Text>)}
      {max > 0 ? <Text dimColor>{o > 0 ? `${o} more below` : "arrows scroll"}</Text> : null}
    </Box>
  );
}

export function ErrorView(p: { message: string; raw?: string }) {
  const raw = (p.raw ?? "").trim().split("\n").slice(-15);
  return (
    <Box flexDirection="column">
      <Text color="red" bold>{p.message}</Text>
      {raw.length && raw[0] ? <Box flexDirection="column" marginLeft={2}>{raw.map((l, i) => <Text key={i} dimColor>{l}</Text>)}</Box> : null}
    </Box>
  );
}

export function Table(p: { head: string[]; rows: string[][] }) {
  const w = p.head.map((h, i) => Math.max(h.length, ...p.rows.map((r) => (r[i] ?? "").length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(w[i] ?? 0)).join("  ");
  return (
    <Box flexDirection="column">
      <Text bold>{line(p.head)}</Text>
      {p.rows.length === 0 ? <Text dimColor>(none)</Text> : p.rows.map((r, i) => <Text key={i}>{line(r)}</Text>)}
    </Box>
  );
}
