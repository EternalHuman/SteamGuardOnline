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

const cryptoModule = await import("../public/crypto.js");
const {
  PRIMARY_ALPHABET,
  createAccessEnvelope,
  createEncryptedPayload,
  decryptEncryptedPayload,
  disposePreparedAccess,
  generateSteamGuardCode,
  prepareAccessCode,
  randomPrimaryCode,
  unwrapDataKeyWithPreparedAccess,
  validateAlias,
} = cryptoModule;

const TEST_SECRET = "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA=";

test("Steam Guard generation matches known vectors", async () => {
  assert.equal(await generateSteamGuardCode(TEST_SECRET, 0), "T87KC");
  assert.equal(await generateSteamGuardCode(TEST_SECRET, 30_000), "CD6KH");
  assert.equal(await generateSteamGuardCode(TEST_SECRET, 1_700_000_000_000), "8T2JP");
  assert.equal(await generateSteamGuardCode(TEST_SECRET, 1_712_345_678_000), "DTXQC");
});

test("primary ID is exactly 16 characters from the configured alphabet", () => {
  for (let iteration = 0; iteration < 50; iteration += 1) {
    const code = randomPrimaryCode();
    assert.equal(code.length, 16);
    assert.ok([...code].every((character) => PRIMARY_ALPHABET.includes(character)));
  }
});

test("encrypted payload can be opened with the matching access code", async () => {
  const accessCode = "super_secret_code123";
  const payload = { v: 1, sharedSecret: TEST_SECRET, label: "test-account" };
  const encrypted = await createEncryptedPayload(payload);
  const envelope = await createAccessEnvelope(accessCode, encrypted.dataKey);
  const prepared = await prepareAccessCode(accessCode);

  try {
    assert.equal(prepared.token, envelope.token);
    const unwrappedKey = await unwrapDataKeyWithPreparedAccess(envelope.wrap, prepared);
    const decrypted = await decryptEncryptedPayload(encrypted.payload, unwrappedKey);
    assert.deepEqual(decrypted, payload);
    unwrappedKey.fill(0);
  } finally {
    encrypted.dataKey.fill(0);
    disposePreparedAccess(prepared);
  }
});

test("a different access code cannot unwrap the data key", async () => {
  const encrypted = await createEncryptedPayload({ v: 1, sharedSecret: TEST_SECRET });
  const envelope = await createAccessEnvelope("super_secret_code123", encrypted.dataKey);
  const wrongPrepared = await prepareAccessCode("another_secret_code456!");

  try {
    await assert.rejects(
      () => unwrapDataKeyWithPreparedAccess(envelope.wrap, wrongPrepared),
      /Не удалось расшифровать данные/,
    );
  } finally {
    encrypted.dataKey.fill(0);
    disposePreparedAccess(wrongPrepared);
  }
});

test("alias validation accepts custom codes from three characters", () => {
  assert.equal(validateAlias("super_secret_code123").ok, true);
  assert.equal(validateAlias("aB1").ok, true);
  assert.equal(validateAlias("ab").ok, false);
  assert.equal(validateAlias("кириллица_не_разрешена123").ok, false);
});
