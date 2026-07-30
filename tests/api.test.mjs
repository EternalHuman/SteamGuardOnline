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
if (!globalThis.atob) {
  Object.defineProperty(globalThis, "atob", {
    value: (value) => Buffer.from(value, "base64").toString("binary"),
    configurable: true,
  });
}

const { onRequest } = await import("../functions/api/[[path]].js");
const { createAccessEnvelope, createEncryptedPayload } = await import("../public/crypto.js");

const TEST_SECRET = "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA=";

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

  async list({ prefix = "", cursor = "", limit = 1000 } = {}) {
    const offset = Number(cursor || 0);
    const names = [...this.values.keys()].filter((key) => key.startsWith(prefix)).sort();
    const pageNames = names.slice(offset, offset + limit);
    const nextOffset = offset + pageNames.length;
    const listComplete = nextOffset >= names.length;
    return {
      keys: pageNames.map((name) => ({ name })),
      list_complete: listComplete,
      cursor: listComplete ? undefined : String(nextOffset),
    };
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

function savedEncrypted(character = "I") {
  return {
    v: 1,
    salt: character.repeat(22),
    iv: character.repeat(16),
    ciphertext: character.repeat(43),
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
  const importData = await imported.json();
  assert.match(importData.recordId, /^[A-Za-z0-9_-]{24}$/);

  const primaryLookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(primaryLookup.status, 200);
  const primaryData = await primaryLookup.json();
  assert.equal(primaryData.kind, "primary");
  assert.equal(primaryData.recordId, importData.recordId);
  assert.equal(primaryData.hasAlias, true);
  assert.deepEqual(primaryData.payload, payload("D"));

  const aliasLookup = await call(kv, "/api/lookup", { token: aliasToken });
  assert.equal(aliasLookup.status, 200);
  const aliasData = await aliasLookup.json();
  assert.equal(aliasData.kind, "alias");
  assert.equal(aliasData.recordId, importData.recordId);

  const updatedPayload = payload("U");
  const updatedPayloadResponse = await call(kv, "/api/update-payload", {
    token: aliasToken,
    payload: updatedPayload,
  });
  assert.equal(updatedPayloadResponse.status, 200);
  assert.equal((await updatedPayloadResponse.json()).updated, true);

  const updatedLookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(updatedLookup.status, 200);
  assert.deepEqual((await updatedLookup.json()).payload, updatedPayload);

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

test("unsafe code endpoint decrypts a vault server-side and returns a Steam Guard code", async () => {
  const kv = new FakeKV();
  const accessCode = "unsafe_api_access123";
  const originalNow = Date.now;
  let encrypted;
  Date.now = () => 1_700_000_000_000;

  try {
    encrypted = await createEncryptedPayload({
      v: 1,
      sharedSecret: TEST_SECRET,
      label: "api-account",
    });
    const primary = await createAccessEnvelope(accessCode, encrypted.dataKey);

    const imported = await call(kv, "/api/import", {
      payload: encrypted.payload,
      primary,
    });
    assert.equal(imported.status, 201);

    const response = await call(kv, "/api/unsafe-code", { accessCode });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      ok: true,
      unsafe: true,
      code: "8T2JP",
      secondsRemaining: 10,
      remainingFraction: 1 / 3,
      step: 56666666,
      validUntil: "2023-11-14T22:13:30.000Z",
      kind: "primary",
      recordId: (await imported.json()).recordId,
      label: "api-account",
    });
  } finally {
    Date.now = originalNow;
    if (encrypted?.dataKey instanceof Uint8Array) encrypted.dataKey.fill(0);
  }
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

test("API bulk upload rate limits allow 50 requests per minute", async () => {
  const kv = new FakeKV();
  const originalNow = Date.now;
  Date.now = () => 1_700_000_000_000;
  const tokens = [];

  try {
    for (let index = 0; index < 50; index += 1) {
      const primaryToken = `T${String(index).padStart(2, "0")}${"A".repeat(40)}`;
      tokens.push(primaryToken);
      const imported = await call(kv, "/api/import", {
        payload: payload("R"),
        primary: { token: primaryToken, wrap: wrap("S") },
      });
      assert.equal(imported.status, 201);
    }

    const limited = await call(kv, "/api/import", {
      payload: payload("T"),
      primary: { token: `T50${"A".repeat(40)}`, wrap: wrap("U") },
    });
    assert.equal(limited.status, 429);

    for (let index = 0; index < 50; index += 1) {
      const saved = await call(kv, "/api/save-saved", {
        id: `P${String(index).padStart(2, "0")}${"B".repeat(21)}`,
        accessToken: tokens[index],
        verifier: `V${String(index).padStart(2, "0")}${"C".repeat(40)}`,
        encrypted: savedEncrypted("D"),
      });
      assert.equal(saved.status, 200);
    }

    const limitedSave = await call(kv, "/api/save-saved", {
      id: `P50${"B".repeat(21)}`,
      accessToken: tokens[0],
      verifier: `V50${"C".repeat(40)}`,
      encrypted: savedEncrypted("E"),
    });
    assert.equal(limitedSave.status, 429);
  } finally {
    Date.now = originalNow;
  }
});

test("API can delete a saved profile vault by saved profile id", async () => {
  const kv = new FakeKV();
  const primaryToken = token("D");
  const aliasToken = token("E");
  const profileId = "P".repeat(24);

  const imported = await call(kv, "/api/import", {
    payload: payload("F"),
    primary: { token: primaryToken, wrap: wrap("G") },
    alias: { token: aliasToken, wrap: wrap("H") },
  });
  assert.equal(imported.status, 201);

  const saved = await call(kv, "/api/save-saved", {
    id: profileId,
    accessToken: aliasToken,
    verifier: token("V"),
    encrypted: savedEncrypted("I"),
  });
  assert.equal(saved.status, 200);

  const deleted = await call(kv, "/api/delete-saved", { id: profileId });
  assert.equal(deleted.status, 200);
  assert.equal((await deleted.json()).deleted, true);

  const primaryLookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(primaryLookup.status, 404);

  const aliasLookup = await call(kv, "/api/lookup", { token: aliasToken });
  assert.equal(aliasLookup.status, 404);
});

test("saved profile PIN failures are counted in KV and delete the vault", async () => {
  const kv = new FakeKV();
  const primaryToken = token("J");
  const profileId = "Q".repeat(24);
  const verifier = token("K");
  const encrypted = savedEncrypted("L");

  const imported = await call(kv, "/api/import", {
    payload: payload("M"),
    primary: { token: primaryToken, wrap: wrap("N") },
  });
  assert.equal(imported.status, 201);

  const saved = await call(kv, "/api/save-saved", {
    id: profileId,
    accessToken: primaryToken,
    verifier,
    encrypted,
  });
  assert.equal(saved.status, 200);

  const firstWrong = await call(kv, "/api/open-saved", { id: profileId, verifier: token("W") });
  assert.equal(firstWrong.status, 403);
  assert.deepEqual(await firstWrong.json(), {
    ok: false,
    error: "Неверный PIN.",
    deleted: false,
    attemptsLeft: 4,
  });

  const correct = await call(kv, "/api/open-saved", { id: profileId, verifier });
  assert.equal(correct.status, 200);
  assert.deepEqual((await correct.json()).encrypted, encrypted);

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const wrong = await call(kv, "/api/open-saved", { id: profileId, verifier: token(String(attempt)) });
    assert.equal(wrong.status, 403);
    assert.equal((await wrong.json()).deleted, false);
  }

  const deletedByLimit = await call(kv, "/api/open-saved", { id: profileId, verifier: token("X") });
  assert.equal(deletedByLimit.status, 403);
  const deletedBody = await deletedByLimit.json();
  assert.equal(deletedBody.deleted, true);
  assert.equal(deletedBody.attemptsLeft, 0);

  const lookup = await call(kv, "/api/lookup", { token: primaryToken });
  assert.equal(lookup.status, 404);

  const openAfterDelete = await call(kv, "/api/open-saved", { id: profileId, verifier });
  assert.equal(openAfterDelete.status, 404);
});

test("stats endpoint reports profile count and latest creation timestamps with rate limiting", async () => {
  const kv = new FakeKV();
  const timestamps = [
    "2026-07-30T08:00:00.000Z",
    "2026-07-30T08:01:00.000Z",
    "2026-07-30T08:02:00.000Z",
    "2026-07-30T08:03:00.000Z",
    "2026-07-30T08:04:00.000Z",
    "2026-07-30T08:05:00.000Z",
  ];

  for (const [index, createdAt] of timestamps.entries()) {
    await kv.put(
      `record:${String(index).padStart(2, "0")}`,
      JSON.stringify({
        v: 1,
        payload: payload("S"),
        primaryToken: token(String(index)),
        aliasToken: null,
        createdAt,
        updatedAt: createdAt,
      }),
    );
  }
  await kv.put("access:not-counted", JSON.stringify({ v: 1, createdAt: "2099-01-01T00:00:00.000Z" }));
  await kv.put("saved-profile:not-counted", JSON.stringify({ v: 1, createdAt: "2099-01-01T00:00:00.000Z" }));

  const response = await call(kv, "/api/stats", null, "GET");
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.ok, true);
  assert.equal(data.profileCount, 6);
  assert.deepEqual(data.latestProfileCreatedAt, timestamps.slice(1).reverse());
  assert.match(data.generatedAt, /^\d{4}-\d{2}-\d{2}T/);

  const limited = await call(kv, "/api/stats", null, "GET");
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "60");
});

test("health endpoint reports readiness", async () => {
  const kv = new FakeKV();
  const response = await call(kv, "/api/health", null, "GET");
  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
});

test("GET /api serves the API documentation page without KV", async () => {
  const request = new Request("https://example.com/api", { method: "GET" });
  const response = await onRequest({
    request,
    env: {
      ASSETS: {
        fetch(assetRequest) {
          assert.equal(new URL(assetRequest.url).pathname, "/index.html");
          return new Response("<!doctype html><title>SGO</title>", {
            headers: { "content-type": "text/html; charset=utf-8" },
          });
        },
      },
    },
  });

  assert.equal(response.status, 200);
  assert.match(await response.text(), /<!doctype html>/i);
});

test("GET /api/config serves Cloudflare deploy metadata without KV", async () => {
  const request = new Request("https://example.com/api/config", { method: "GET" });
  const githubCommit = "355c01b532d9c205c72f1000846cf2a45995c3e7";
  const response = await onRequest({
    request,
    env: {
      CF_PAGES_URL: "https://abcdef12.steamguardonline.pages.dev/some/path",
      CF_PAGES_COMMIT_SHA: githubCommit.toUpperCase(),
      SGO_FIXED_DEPLOY_URL: "https://manual99.steamguardonline.pages.dev",
      SGO_GITHUB_COMMIT: "1111111111111111111111111111111111111111",
    },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    fixedDeployUrl: "https://abcdef12.steamguardonline.pages.dev",
    githubCommit,
  });
});
