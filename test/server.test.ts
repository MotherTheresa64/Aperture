import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/server.ts";

async function withServer(fn: (url: string) => Promise<void>): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const post = (url: string, path: string, body: unknown) =>
  fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

test("the page is served", async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Aperture/);
  });
});

test("a password hashes and verifies, and the wrong one does not", async () => {
  await withServer(async (url) => {
    const hashed = await (await post(url, "/hash", { password: "correct horse battery staple" })).json();
    assert.match(hashed.stored, /^scrypt\$/);

    const right = await (await post(url, "/verify", { password: "correct horse battery staple", stored: hashed.stored })).json();
    assert.equal(right.valid, true);

    const wrong = await (await post(url, "/verify", { password: "wrong password", stored: hashed.stored })).json();
    assert.equal(wrong.valid, false);

    assert.equal((await post(url, "/hash", { password: "short" })).status, 400);
  });
});

test("the TOTP code matches what the verifier accepts", async () => {
  await withServer(async (url) => {
    const secret = "JBSWY3DPEHPK3PXP";
    const current = await (await fetch(`${url}/totp?secret=${secret}`)).json();
    assert.match(current.code, /^\d{6}$/);
    assert.ok(current.remaining >= 1 && current.remaining <= 30);

    const accepted = await (await post(url, "/verify-totp", { secret, code: current.code })).json();
    assert.equal(accepted.valid, true);

    const rejected = await (await post(url, "/verify-totp", { secret, code: "000000" })).json();
    assert.equal(rejected.valid, false);
  });
});

test("a session issues, resolves and revokes", async () => {
  await withServer(async (url) => {
    const issued = await (await post(url, "/session", { userId: "user-42" })).json();
    assert.equal(issued.userId, "user-42");
    assert.ok(issued.token.length > 20);

    const resolved = await (await fetch(`${url}/session?token=${encodeURIComponent(issued.token)}`)).json();
    assert.equal(resolved.userId, "user-42");

    await fetch(`${url}/session?token=${encodeURIComponent(issued.token)}`, { method: "DELETE" });

    const after = await (await fetch(`${url}/session?token=${encodeURIComponent(issued.token)}`)).json();
    assert.equal(after.userId, null);
  });
});
