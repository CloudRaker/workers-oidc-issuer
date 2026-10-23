import { DurableObject } from "cloudflare:workers";
import { CF_API_BASE, findSecretId, writeSecret } from "./cfapi.js";
import { type Env, type Policy, policyFingerprint } from "./config.js";
import { fingerprint, importPrivate, type KeysetKey, type Keyset, MEMBERS, parseKeyset, type PrivateJwk, RSA_ALG } from "./keys.js";

export type Status = "next" | "active" | "retiring" | "deleted";
type Row = { kid: string; fp: string; created: number; status: Status; activate_at: number | null; retire_at: number | null };

export type TickReport = {
  kids: { kid: string; fp: string; status: Status; created: number; activateAt?: number; retireAt?: number }[];
  changed: boolean;
  warnings: string[];
  nextEventAt?: number;
};

const H = 3600;
// Secrets Store propagation is ~5 s. A keyset behind the DO's version inside this window is lag, not loss.
const LAG_S = 60;
// ponytail: global backoff after a failed write; the per-isolate 10 s heal timer is not a global bound.
const BACKOFF_S = 60;

async function generate(now: number): Promise<{ jwk: PrivateJwk; fp: string }> {
  const kp = (await crypto.subtle.generateKey({ ...RSA_ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = (await crypto.subtle.exportKey("jwk", kp.privateKey)) as unknown as Record<string, unknown>;
  const kid = `k${now}${Array.from(crypto.getRandomValues(new Uint8Array(2)), (b) => b.toString(16).padStart(2, "0")).join("")}`;
  const jwk = { ...Object.fromEntries(MEMBERS.map((m) => [m, raw[m]])), kid, alg: "RS256", use: "sig", kty: "RSA" } as PrivateJwk;
  return { jwk, fp: await fingerprint(jwk) };
}

/**
 * Provenance pin and rotation clock for auto mode. SQLite holds (kid, fp, timestamps) only.
 * Private JWKs live in memory between generation and the Secrets Store write; never in storage.
 */
export class KeyRing extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY, fp TEXT NOT NULL, created INTEGER NOT NULL, status TEXT NOT NULL, activate_at INTEGER, retire_at INTEGER);" +
        "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)",
    );
  }

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private meta(k: string): string | null {
    const r = this.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0];
    return r ? r.v : null;
  }

  private rows(): Row[] {
    return this.sql.exec<Row>("SELECT kid, fp, created, status, activate_at, retire_at FROM keys WHERE status != 'deleted' ORDER BY created").toArray();
  }

  private report(rows: Row[]): TickReport["kids"] {
    return rows.filter((r) => r.status !== "deleted").map((r) => ({ kid: r.kid, fp: r.fp, status: r.status, created: r.created, ...(r.activate_at !== null ? { activateAt: r.activate_at } : {}), ...(r.retire_at !== null ? { retireAt: r.retire_at } : {}) }));
  }

  /** Pure read: live rows whose (kid, fp) match, with the DO's status (the signer picks the active key from this, not from the keyset). */
  async confirm(entries: { kid: string; fp: string }[]): Promise<{ kid: string; status: Status }[]> {
    const rows = this.rows();
    return entries.flatMap((e) => {
      const r = rows.find((r) => r.kid === e.kid && r.fp === e.fp);
      return r ? [{ kid: r.kid, status: r.status }] : [];
    });
  }

  // In memory on purpose: nothing is persisted on a failed tick (spec 6.13); an eviction costs one extra attempt.
  private lastFail: { at: number; fp: string } | null = null;

  /** `now` (unix seconds) is for tests only. */
  async tick(policy: Policy, now: number = Math.floor(Date.now() / 1000)): Promise<TickReport> {
    const fp = policyFingerprint(policy);
    // A throw inside blockConcurrencyWhile resets the object; catch inside, rethrow outside.
    const r = await this.ctx.blockConcurrencyWhile(async (): Promise<{ ok: TickReport } | { err: unknown }> => {
      if (this.lastFail && this.lastFail.fp === fp && now - this.lastFail.at < BACKOFF_S) {
        return { ok: { kids: this.report(this.rows()), changed: false, warnings: ["tick backoff"] } };
      }
      try {
        return { ok: await this.runTick(policy, now) };
      } catch (err) {
        this.lastFail = { at: now, fp };
        return { err };
      }
    });
    if ("err" in r) throw r.err;
    return r.ok;
  }

  private async runTick(policy: Policy, now: number): Promise<TickReport> {
    // Whole-tick budget: secret reads, keygen and every API call must fit inside the 30 s blockConcurrencyWhile limit.
    const deadline = Date.now() + 25_000;
    const warnings: string[] = [];
    let changed = false;
    const rows = this.rows();
    const metaVersion = Number(this.meta("keyset_version") ?? "0");

    // 1-2. Current keyset, filtered by provenance; DO rows are the truth.
    // A failed read is not an empty keyset: rows without material are deleted below and the private material
    // exists nowhere else. The CLI seeds the EMPTY document before the first deploy, so a throw here is a
    // misconfiguration or an outage; it propagates and nothing is persisted.
    const raw = await (this.env.OIDC_KEYSET as SecretsStoreSecret).get();
    const ks: Keyset | null = parseKeyset(raw);
    // Propagation lag: the binding still serves the value before our last PATCH. Rows are truth; never drop them here.
    const behind = metaVersion > 0 && (!ks || ks.version < metaVersion);
    if (behind && now - Number(this.meta("last_write") ?? "0") < LAG_S) {
      warnings.push("keyset behind the DO; waiting for propagation");
      return { kids: this.report(rows), changed: false, warnings, nextEventAt: now + LAG_S };
    }
    const material = new Map<string, PrivateJwk>();
    if (!ks) {
      if (rows.length > 0) {
        warnings.push("keyset missing or invalid; rewriting");
        changed = true;
      }
    } else {
      for (const k of ks.keys) {
        const row = rows.find((r) => r.kid === k.kid);
        const { created: _c, status: _s, activateAt: _a, retireAt: _r, ...jwk } = k as KeysetKey;
        // fp pins (n, e) only; the private members are attacker-writable, so they must also sign for (n, e).
        if (row && row.fp === (await fingerprint(k)) && (await importPrivate(jwk as PrivateJwk))) {
          material.set(k.kid, jwk as PrivateJwk);
        } else {
          warnings.push(`dropped unknown or unusable key: kid=${k.kid}`);
          changed = true;
        }
      }
      if (ks.version < metaVersion) {
        warnings.push("keyset version behind; rewriting");
        changed = true;
      }
    }
    for (const r of rows) {
      if (!material.has(r.kid)) {
        warnings.push(`key material lost: kid=${r.kid}`);
        r.status = "deleted";
        changed = true;
      }
    }
    const live = () => rows.filter((r) => r.status !== "deleted");
    const active = () => live().find((r) => r.status === "active");
    const build = (version: number): Keyset => ({
      v: 1,
      version,
      active: active()?.kid ?? "",
      keys: live().map((r) => {
        const k: KeysetKey = { ...(material.get(r.kid) as PrivateJwk), created: r.created, status: r.status as KeysetKey["status"] };
        if (r.activate_at !== null) k.activateAt = r.activate_at;
        if (r.retire_at !== null) k.retireAt = r.retire_at;
        return k;
      }),
    });
    // Provenance covers the whole record: anything that is not byte-for-byte what this DO last wrote
    // (active, status, created, timestamps, version, member order) is rewritten.
    if (ks && JSON.stringify(build(metaVersion)) !== raw) {
      warnings.push("keyset differs from DO state; rewriting");
      changed = true;
    }
    const fresh = async (status: Status, extra: Partial<Row> = {}): Promise<void> => {
      const g = await generate(now);
      material.set(g.jwk.kid, g.jwk);
      rows.push({ kid: g.jwk.kid, fp: g.fp, created: now, status, activate_at: null, retire_at: null, ...extra });
      changed = true;
    };
    const grace = policy.graceHours * H;

    // 3. Policy events.
    const revoke = policy.revokeBefore !== "" && policy.revokeBefore !== this.meta("last_revoke_before");
    if (revoke) {
      const before = Math.floor(Date.parse(policy.revokeBefore) / 1000);
      for (const r of live()) {
        if (r.created < before) {
          r.status = "retiring";
          r.retire_at = now;
          changed = true;
        }
      }
    }
    const rotate = policy.rotateNonce !== (this.meta("last_nonce") ?? "");
    if (rotate && active() && !live().some((r) => r.status === "next")) await fresh("next", { activate_at: now + grace });
    for (const kid of policy.retireKids) {
      const r = live().find((x) => x.kid === kid);
      if (!r) continue;
      if (r.status === "active") {
        warnings.push(`retire ignored for active key: kid=${kid}`);
        continue;
      }
      r.status = "retiring";
      r.retire_at = now;
      changed = true;
    }

    // 4. Schedule.
    if (!active()) await fresh("active");
    const act = active() as Row;
    if (!live().some((r) => r.status === "next") && act.created + policy.intervalHours * H - grace <= now) await fresh("next", { activate_at: now + grace });
    const next = live().find((r) => r.status === "next");
    if (next && next.activate_at !== null && next.activate_at <= now) {
      act.status = "retiring";
      act.retire_at = now + grace;
      next.status = "active";
      next.activate_at = null;
      changed = true;
    }
    for (const r of live()) {
      if (r.status === "retiring" && r.retire_at !== null && r.retire_at <= now) {
        r.status = "deleted";
        changed = true;
      }
    }
    // ponytail: hard cap of 3 live keys; grace < interval/2 already guarantees it, this is the belt.
    while (live().length > 3) {
      const oldest = live().filter((r) => r.status === "retiring").sort((a, b) => a.created - b.created)[0] ?? (live()[0] as Row);
      oldest.status = "deleted";
    }

    // 5. Write, then persist.
    if (changed) {
      const version = metaVersion + 1;
      const keyset = build(version);
      const env = this.env as Record<string, unknown>;
      const api = {
        fetcher: (this.env.CF_API ?? globalThis) as { fetch: typeof fetch },
        base: CF_API_BASE,
        token: await (this.env.CF_API_TOKEN as SecretsStoreSecret).get(),
        accountId: String(env["CF_ACCOUNT_ID"]),
        storeId: String(env["SECRETS_STORE_ID"]),
        deadline,
      };
      const name = String(env["KEYSET_SECRET_NAME"] ?? "OIDC_KEYSET");
      const resolve = async (): Promise<string> => {
        const id = await findSecretId(api, name);
        if (!id) throw new Error("keyset secret not found in the store");
        return id;
      };
      const cached = this.meta("secret_name") === name ? this.meta("secret_id") : null;
      let secretId = cached ?? (await resolve());
      const body = JSON.stringify(keyset);
      try {
        await writeSecret(api, secretId, body);
      } catch (e) {
        // The cached id goes stale when the secret is deleted and recreated. On an HTTP error re-resolve by
        // name and retry once, only if the id changed. A freshly resolved id has nothing to re-resolve; transport
        // errors (timeout) rethrow. Every call shares the tick deadline.
        if (cached === null || !(e instanceof Error && e.message.includes("HTTP"))) throw e;
        const fresh = await resolve();
        if (fresh === secretId) throw e;
        secretId = fresh;
        await writeSecret(api, secretId, body);
      }
      material.clear();
      const sid = secretId;
      this.ctx.storage.transactionSync(() => {
        for (const r of rows) {
          this.sql.exec("INSERT OR REPLACE INTO keys(kid, fp, created, status, activate_at, retire_at) VALUES (?, ?, ?, ?, ?, ?)", r.kid, r.fp, r.created, r.status, r.activate_at, r.retire_at);
        }
        for (const [k, v] of [["keyset_version", String(version)], ["secret_id", sid], ["secret_name", name], ["last_tick", String(now)], ["last_write", String(now)]] as const) this.sql.exec("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", k, v);
      });
    } else {
      this.sql.exec("INSERT OR REPLACE INTO meta(k, v) VALUES ('last_tick', ?)", String(now));
    }
    if (revoke) this.sql.exec("INSERT OR REPLACE INTO meta(k, v) VALUES ('last_revoke_before', ?)", policy.revokeBefore);
    if (rotate) this.sql.exec("INSERT OR REPLACE INTO meta(k, v) VALUES ('last_nonce', ?)", policy.rotateNonce);

    // 6. Report (no private material).
    const times: number[] = [];
    for (const r of live()) {
      if (r.activate_at !== null) times.push(r.activate_at);
      if (r.retire_at !== null) times.push(r.retire_at);
      if (r.status === "active") times.push(r.created + policy.intervalHours * H - grace);
    }
    const report: TickReport = { kids: this.report(rows), changed, warnings };
    const future = times.filter((t) => t > now);
    if (future.length) report.nextEventAt = Math.min(...future);
    return report;
  }
}
