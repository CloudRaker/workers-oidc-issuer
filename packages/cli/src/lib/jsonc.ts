import jsonc from "jsonc-parser";

const FMT = { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } };

type Binding = { binding: string; store_id: string; secret_name: string };
type Config = {
  name?: string;
  account_id?: string;
  vars?: Record<string, string>;
  secrets_store_secrets?: Binding[];
  durable_objects?: { bindings?: { name: string; class_name: string }[] };
  triggers?: { crons?: string[] };
};

export function parseConfig(text: string): Config {
  const errors: jsonc.ParseError[] = [];
  const cfg = jsonc.parse(text, errors, { allowTrailingComma: true }) as Config | undefined;
  if (errors.length > 0 || typeof cfg !== "object" || cfg === null) throw new Error("wrangler.jsonc: parse error");
  return cfg;
}

function edit(text: string, path: jsonc.JSONPath, value: unknown, opts: jsonc.ModificationOptions = FMT): string {
  return jsonc.applyEdits(text, jsonc.modify(text, path, value, opts));
}

// jsonc-parser's modify() inserts after the previous value and removes from the previous value's end, so a
// trailing "// comment" slides onto the neighbouring property. Properties are spliced by whole line instead.
const TRAIL = /^[ \t]*(,)?[ \t]*(\/\/[^\n]*)?/;

function lineStart(text: string, offset: number): number {
  return text.lastIndexOf("\n", offset - 1) + 1;
}

function ownsLine(text: string, node: jsonc.Node): boolean {
  return /^[ \t]*$/.test(text.slice(lineStart(text, node.offset), node.offset));
}

/** Sets object[key]; a new key goes on its own line after `after` (or last). */
function setProp(text: string, objPath: jsonc.JSONPath, key: string, value: unknown, after?: string): string {
  const obj = jsonc.findNodeAtLocation(jsonc.parseTree(text) ?? { type: "null", offset: 0, length: 0 }, objPath);
  const props = obj?.type === "object" ? (obj.children ?? []) : [];
  if (props.some((p) => p.children?.[0]?.value === key)) return edit(text, [...objPath, key], value);
  const prev = (after && props.find((p) => p.children?.[0]?.value === after)) ?? props[props.length - 1];
  if (!prev || !ownsLine(text, prev)) return edit(text, [...objPath, key], value);
  const prevEnd = prev.offset + prev.length;
  const trail = TRAIL.exec(text.slice(prevEnd)) as RegExpExecArray;
  const comma = trail[1] ? "" : ",";
  const indent = text.slice(lineStart(text, prev.offset), prev.offset);
  const isLast = props[props.length - 1] === prev;
  const line = `\n${indent}${JSON.stringify(key)}: ${JSON.stringify(value)}${isLast ? "" : ","}`;
  const eol = prevEnd + trail[0].length;
  return text.slice(0, prevEnd) + comma + text.slice(prevEnd, eol) + line + text.slice(eol);
}

function removeProp(text: string, path: jsonc.JSONPath): string {
  const node = jsonc.findNodeAtLocation(jsonc.parseTree(text) ?? { type: "null", offset: 0, length: 0 }, path);
  const prop = node?.parent;
  if (!node) return text;
  if (!prop || prop.type !== "property" || !ownsLine(text, prop)) return edit(text, path, undefined);
  const start = lineStart(text, prop.offset);
  const propEnd = prop.offset + prop.length;
  const trail = TRAIL.exec(text.slice(propEnd)) as RegExpExecArray;
  let end = propEnd + trail[0].length;
  if (text[end] === "\n") end++;
  let out = text.slice(0, start) + text.slice(end);
  if (!trail[1]) {
    // removed the last property: drop the comma that now dangles after the previous one
    const siblings = prop.parent?.children ?? [];
    const prev = siblings[siblings.indexOf(prop) - 1];
    if (prev) {
      const prevEnd = prev.offset + prev.length;
      const m = /^[ \t]*,/.exec(out.slice(prevEnd));
      if (m) out = out.slice(0, prevEnd) + out.slice(prevEnd + m[0].length - 1).replace(/^,/, "");
    }
  }
  return out;
}

export function setVar(text: string, name: string, value: string): string {
  return setProp(text, ["vars"], name, value);
}

export function removeVar(text: string, name: string): string {
  return removeProp(text, ["vars", name]);
}

export function setActiveKid(text: string, kid: string): string {
  return setVar(text, "ACTIVE_KID", kid);
}

export function setIssuer(text: string, issuer: string): string {
  return setVar(text, "ISSUER", issuer);
}

export function setAccountId(text: string, accountId: string): string {
  return setProp(text, [], "account_id", accountId, "compatibility_flags");
}

export function addSecretBinding(text: string, b: Binding): string {
  const list = parseConfig(text).secrets_store_secrets ?? [];
  const i = list.findIndex((x) => x.binding === b.binding);
  if (i >= 0) return edit(text, ["secrets_store_secrets", i], b);
  return edit(text, ["secrets_store_secrets", -1], b, { ...FMT, isArrayInsertion: true });
}

export function removeSecretBinding(text: string, binding: string): string {
  const list = parseConfig(text).secrets_store_secrets ?? [];
  const i = list.findIndex((x) => x.binding === binding);
  return i < 0 ? text : edit(text, ["secrets_store_secrets", i], undefined);
}

/** Kids that have an OIDC_KEY_<kid> binding, sorted. */
export function bindingKids(cfg: Config): string[] {
  return (cfg.secrets_store_secrets ?? [])
    .map((b) => b.binding)
    .filter((b) => b.startsWith("OIDC_KEY_"))
    .map((b) => b.slice(9))
    .sort();
}

const AUTO_VARS = ["CF_ACCOUNT_ID", "SECRETS_STORE_ID", "KEYSET_SECRET_NAME", "ROTATION_INTERVAL_HOURS", "ROTATION_GRACE_HOURS", "ROTATE_NONCE", "REVOKE_BEFORE", "RETIRE_KIDS"];

export function enableAutoMode(text: string, o: { accountId: string; storeId: string; keysetSecretName?: string }): string {
  const name = o.keysetSecretName ?? "OIDC_KEYSET";
  const cur = parseConfig(text).vars ?? {};
  // a re-run keeps the operator's schedule and nonce: a reset nonce would start a rotation nobody asked for
  const keep = (k: string, d: string): string => cur[k] ?? d;
  let t = text;
  for (const [k, v] of [
    ["ROTATION", "auto"], ["CF_ACCOUNT_ID", o.accountId], ["SECRETS_STORE_ID", o.storeId], ["KEYSET_SECRET_NAME", name],
    ["ROTATION_INTERVAL_HOURS", keep("ROTATION_INTERVAL_HOURS", "720")], ["ROTATION_GRACE_HOURS", keep("ROTATION_GRACE_HOURS", "24")],
    ["ROTATE_NONCE", keep("ROTATE_NONCE", "")], ["REVOKE_BEFORE", keep("REVOKE_BEFORE", "")], ["RETIRE_KIDS", keep("RETIRE_KIDS", "[]")],
  ] as const) t = setVar(t, k, v);
  t = removeVar(t, "ACTIVE_KID");
  for (const kid of bindingKids(parseConfig(t))) t = removeSecretBinding(t, `OIDC_KEY_${kid}`);
  t = addSecretBinding(t, { binding: "OIDC_KEYSET", store_id: o.storeId, secret_name: name });
  t = addSecretBinding(t, { binding: "CF_API_TOKEN", store_id: o.storeId, secret_name: "OIDC_CF_API_TOKEN" });
  t = setProp(t, [], "durable_objects", { bindings: [{ name: "KEYRING", class_name: "KeyRing" }] }, "secrets_store_secrets");
  if (!Object.hasOwn(parseConfig(t), "migrations")) t = setProp(t, [], "migrations", [{ tag: "v1", new_sqlite_classes: ["KeyRing"] }], "durable_objects");
  t = setProp(t, [], "triggers", { crons: ["17 * * * *"] }, "migrations");
  return t;
}

/** Without `kid` the existing OIDC_KEY_* bindings and ACTIVE_KID are kept (Setup re-run on a live manual issuer). */
export function enableManualMode(text: string, o: { storeId: string; kid?: string }): string {
  let t = setVar(text, "ROTATION", "manual");
  if (o.kid) t = setActiveKid(t, o.kid);
  for (const k of AUTO_VARS) t = removeVar(t, k);
  t = removeSecretBinding(t, "OIDC_KEYSET");
  t = removeSecretBinding(t, "CF_API_TOKEN");
  if (o.kid) t = addSecretBinding(t, { binding: `OIDC_KEY_${o.kid}`, store_id: o.storeId, secret_name: `OIDC_KEY_${o.kid}` });
  // ponytail: migrations are history and stay; only the binding and the cron go away.
  t = removeProp(t, ["durable_objects"]);
  // an absent "triggers" makes wrangler skip PUT /schedules, so the deployed cron would stay; an empty list clears it
  if (parseConfig(t).triggers) t = setProp(t, [], "triggers", { crons: [] });
  return t;
}

export type Summary = {
  mode: "manual" | "auto";
  issuer: string | undefined;
  activeKid: string | undefined;
  kids: string[];
  accountId: string | undefined;
  storeId: string | undefined;
  name: string | undefined;
};

export function summarize(text: string): Summary {
  const cfg = parseConfig(text);
  const vars = cfg.vars ?? {};
  const first = cfg.secrets_store_secrets?.[0];
  return {
    mode: vars["ROTATION"] === "auto" ? "auto" : "manual",
    issuer: vars["ISSUER"],
    activeKid: vars["ACTIVE_KID"],
    kids: bindingKids(cfg),
    accountId: cfg.account_id,
    storeId: vars["SECRETS_STORE_ID"] ?? first?.store_id,
    name: cfg.name,
  };
}
