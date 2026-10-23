import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { fetchJson } from "../src/lib/http.js";

describe("fetchJson", () => {
  it("rejects with TimeoutError when the host accepts TCP but never answers", async () => {
    const srv = createServer(() => {}).listen(0, "127.0.0.1");
    await new Promise((r) => srv.once("listening", r));
    const port = (srv.address() as { port: number }).port;
    try {
      await expect(fetchJson(`http://127.0.0.1:${port}/x`, 200)).rejects.toMatchObject({ name: "TimeoutError" });
    } finally {
      srv.close();
    }
  });
});
