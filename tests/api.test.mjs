import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
if (!globalThis.btoa) {
  Object.defineProperty(globalThis, "btoa", {
    value: (value) => Buffer.from(value, "binary").toString("base64"),
    configurable: true,
  });
}

const { onRequest } = await import("../functions/api/[[path]].js");

class FakeKV {
  constructor() {
    this.values = new Map();
  }

  async get(key) {
    return this.values.has(key) ? this.values.get(key) : null;
  }

  async put(key, value) {
    this.values.set(key, String(value));
  }

  async delete(key) {
    this.values.delete(key);
  }
}

function token(character) {
  return character.repeat(43);
}

function wrap(character = "A") {
  return {
    v: 1,
    salt: character.repeat(22),
    iv: character.repeat(16),
    ciphertext: character.repeat(64),
  };
}

function payload(character = "B") {
  return {
    v: 1,
    iv: character.repeat(16),
    ciphertext: character.repeat(80),
  };
}

async function call(kv, path, body, method = "POST") {
  const request = new Request(`https://example.com${path}`, {
    method,
    headers: method === "POST" ? { "content-type": "application/json", origin: "https://example.com" } : undefined,
    body: method === "POST" ? JSON.stringify(body) : undefined,
  });
  return onRequest({ request, env: { SDA_KV: kv } });
}

test("API lifecycle: import, lookup, alias, delete", async () => {
  const kv = new FakeKV();
  const primaryToken = token("A");
  const aliasToken = token("B");
  const replacementAliasToken = token("C");

  const imported = await call(kv, "/api/import", {
    payload: payload("D"),
    primary: { token: primaryToken, wrap: wrap("E") },
    alias: { token: aliasToken, wrap: wrap("F") },
  });
  assert.equal(imported.status, 201);

  const primaryLookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(primaryLookup.status, 200);
  const primaryData = await primaryLookup.json();
  assert.equal(primaryData.kind, "primary");
  assert.equal(primaryData.hasAlias, true);
  assert.deepEqual(primaryData.payload, payload("D"));

  const aliasLookup = await call(kv, "/api/lookup", { token: aliasToken });
  assert.equal(aliasLookup.status, 200);
  assert.equal((await aliasLookup.json()).kind, "alias");

  const replaced = await call(kv, "/api/alias", {
    primaryToken,
    alias: { token: replacementAliasToken, wrap: wrap("G") },
  });
  assert.equal(replaced.status, 200);

  const oldAliasLookup = await call(kv, "/api/lookup", { token: aliasToken });
  assert.equal(oldAliasLookup.status, 404);

  const newAliasLookup = await call(kv, "/api/lookup", { token: replacementAliasToken });
  assert.equal(newAliasLookup.status, 200);

  const deleted = await call(kv, "/api/delete", { primaryToken });
  assert.equal(deleted.status, 200);

  const deletedLookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(deletedLookup.status, 404);
});

test("API rejects cross-origin browser requests", async () => {
  const kv = new FakeKV();
  const request = new Request("https://example.com/api/lookup", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://attacker.example" },
    body: JSON.stringify({ token: token("Z") }),
  });
  const response = await onRequest({ request, env: { SDA_KV: kv } });
  assert.equal(response.status, 403);
});

test("health endpoint reports readiness", async () => {
  const kv = new FakeKV();
  const response = await call(kv, "/api/health", null, "GET");
  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
});
