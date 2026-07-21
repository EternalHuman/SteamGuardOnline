const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export const PRIMARY_CODE_LENGTH = 16;
export const PRIMARY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const ALIAS_MIN_LENGTH = 3;
export const ALIAS_MAX_LENGTH = 64;
export const ROOT_KDF_ITERATIONS = 310_000;

const ROOT_KDF_SALT = textEncoder.encode("SDA Cloudflare Pages access root v1");
const LOOKUP_CONTEXT = textEncoder.encode("SDA Cloudflare Pages lookup token v1");
const WRAP_INFO = textEncoder.encode("SDA Cloudflare Pages data-key wrap v1");
const WRAP_AAD = textEncoder.encode("SDA Cloudflare Pages wrapped data key v1");
const PAYLOAD_AAD = textEncoder.encode("SDA Cloudflare Pages encrypted payload v1");
const STEAM_CODE_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

function requireWebCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error("Web Crypto API недоступен в этом браузере.");
  }
}

export function normalizeAccessCode(value) {
  return String(value ?? "").trim();
}

export function isPrimaryCode(value) {
  const code = normalizeAccessCode(value);
  return code.length === PRIMARY_CODE_LENGTH && [...code].every((char) => PRIMARY_ALPHABET.includes(char));
}

export function validateAlias(value) {
  const alias = normalizeAccessCode(value);

  if (alias.length < ALIAS_MIN_LENGTH || alias.length > ALIAS_MAX_LENGTH) {
    return {
      ok: false,
      reason: "alias-length",
      message: `Пользовательский код должен содержать от ${ALIAS_MIN_LENGTH} до ${ALIAS_MAX_LENGTH} символов.`,
    };
  }

  if (!/^[A-Za-z0-9._~!@#$%^&*+=?\-]+$/.test(alias)) {
    return {
      ok: false,
      reason: "alias-characters",
      message: "Разрешены латинские буквы, цифры и символы . _ ~ ! @ # $ % ^ & * + = ? -",
    };
  }

  return { ok: true, value: alias };
}

export function validateAccessCode(value) {
  const code = normalizeAccessCode(value);
  if (isPrimaryCode(code)) {
    return { ok: true, value: code, kind: "primary-format" };
  }

  const aliasValidation = validateAlias(code);
  if (aliasValidation.ok) {
    return { ok: true, value: aliasValidation.value, kind: "alias-format" };
  }

  return {
    ok: false,
    reason: "access-code-format",
    message: `Введите основной ID из ${PRIMARY_CODE_LENGTH} символов или пользовательский код длиной от ${ALIAS_MIN_LENGTH} символов.`,
  };
}

export function randomPrimaryCode(length = PRIMARY_CODE_LENGTH) {
  requireWebCrypto();
  const alphabetLength = PRIMARY_ALPHABET.length;
  const unbiasedUpperBound = Math.floor(256 / alphabetLength) * alphabetLength;
  let result = "";

  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(Math.max(32, (length - result.length) * 2)));
    for (const byte of bytes) {
      if (byte >= unbiasedUpperBound) continue;
      result += PRIMARY_ALPHABET[byte % alphabetLength];
      if (result.length === length) break;
    }
  }

  return result;
}

export function randomBytes(length) {
  requireWebCrypto();
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Некорректное base64url-значение.");
  }

  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function decodeBase64(value) {
  if (typeof value !== "string") {
    throw new Error("Steam shared_secret должен быть строкой.");
  }

  const compact = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!compact || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
    throw new Error("shared_secret имеет некорректный формат base64.");
  }

  const withoutPadding = compact.replace(/=+$/g, "");
  const padded = withoutPadding + "=".repeat((4 - (withoutPadding.length % 4)) % 4);

  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("shared_secret не удалось декодировать.");
  }

  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function validateSharedSecret(sharedSecret) {
  try {
    const bytes = decodeBase64(sharedSecret);
    const validLength = bytes.length >= 16 && bytes.length <= 128;
    bytes.fill(0);
    return validLength;
  } catch {
    return false;
  }
}

async function importAesKey(rawKey, usages) {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, usages);
}

async function deriveAccessRoot(code) {
  requireWebCrypto();
  const normalized = normalizeAccessCode(code);
  const material = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(normalized),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: ROOT_KDF_SALT,
      iterations: ROOT_KDF_ITERATIONS,
    },
    material,
    256,
  );

  return new Uint8Array(bits);
}

async function tokenFromRoot(rootKeyBytes) {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    rootKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", hmacKey, LOOKUP_CONTEXT);
  return toBase64Url(signature);
}

async function deriveWrapKey(rootKeyBytes, salt, usages) {
  const hkdfKey = await crypto.subtle.importKey("raw", rootKeyBytes, { name: "HKDF" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: WRAP_INFO,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

export async function prepareAccessCode(code) {
  const validation = validateAccessCode(code);
  if (!validation.ok) {
    throw new Error(validation.message);
  }

  const rootKey = await deriveAccessRoot(validation.value);
  const token = await tokenFromRoot(rootKey);
  return { code: validation.value, token, rootKey };
}

export function disposePreparedAccess(prepared) {
  if (prepared?.rootKey instanceof Uint8Array) {
    prepared.rootKey.fill(0);
  }
}

export async function wrapDataKeyWithPreparedAccess(dataKeyBytes, prepared) {
  if (!(dataKeyBytes instanceof Uint8Array) || dataKeyBytes.length !== 32) {
    throw new Error("Некорректный ключ данных.");
  }
  if (!(prepared?.rootKey instanceof Uint8Array) || prepared.rootKey.length !== 32) {
    throw new Error("Некорректный корневой ключ доступа.");
  }

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrapKey = await deriveWrapKey(prepared.rootKey, salt, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: WRAP_AAD, tagLength: 128 },
    wrapKey,
    dataKeyBytes,
  );

  return {
    v: 1,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

export async function createAccessEnvelope(code, dataKeyBytes) {
  const prepared = await prepareAccessCode(code);
  try {
    const wrap = await wrapDataKeyWithPreparedAccess(dataKeyBytes, prepared);
    return { token: prepared.token, wrap };
  } finally {
    disposePreparedAccess(prepared);
  }
}

export async function unwrapDataKeyWithPreparedAccess(wrap, prepared) {
  if (!wrap || wrap.v !== 1) {
    throw new Error("Неподдерживаемая версия шифрования ключа.");
  }

  const salt = fromBase64Url(wrap.salt);
  const iv = fromBase64Url(wrap.iv);
  const ciphertext = fromBase64Url(wrap.ciphertext);

  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length !== 48) {
    throw new Error("Повреждены параметры зашифрованного ключа.");
  }

  const wrapKey = await deriveWrapKey(prepared.rootKey, salt, ["decrypt"]);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: WRAP_AAD, tagLength: 128 },
      wrapKey,
      ciphertext,
    );
  } catch {
    throw new Error("Не удалось расшифровать данные. Проверьте секретный код.");
  }

  const dataKey = new Uint8Array(plaintext);
  if (dataKey.length !== 32) {
    dataKey.fill(0);
    throw new Error("Расшифрованный ключ имеет некорректную длину.");
  }
  return dataKey;
}

export async function createEncryptedPayload(payload) {
  requireWebCrypto();
  const serialized = JSON.stringify(payload);
  const plaintext = textEncoder.encode(serialized);
  if (plaintext.length > 8_192) {
    throw new Error("Данные maFile слишком велики после безопасной фильтрации.");
  }

  const dataKey = randomBytes(32);
  const iv = randomBytes(12);
  const aesKey = await importAesKey(dataKey, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: PAYLOAD_AAD, tagLength: 128 },
    aesKey,
    plaintext,
  );

  return {
    dataKey,
    payload: {
      v: 1,
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(ciphertext),
    },
  };
}

export async function decryptEncryptedPayload(payload, dataKeyBytes) {
  if (!payload || payload.v !== 1) {
    throw new Error("Неподдерживаемая версия зашифрованных данных.");
  }
  if (!(dataKeyBytes instanceof Uint8Array) || dataKeyBytes.length !== 32) {
    throw new Error("Некорректный ключ данных.");
  }

  const iv = fromBase64Url(payload.iv);
  const ciphertext = fromBase64Url(payload.ciphertext);
  if (iv.length !== 12 || ciphertext.length < 17 || ciphertext.length > 12_000) {
    throw new Error("Зашифрованные данные повреждены.");
  }

  const aesKey = await importAesKey(dataKeyBytes, ["decrypt"]);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: PAYLOAD_AAD, tagLength: 128 },
      aesKey,
      ciphertext,
    );
  } catch {
    throw new Error("Не удалось расшифровать хранилище.");
  }

  try {
    return JSON.parse(textDecoder.decode(plaintext));
  } catch {
    throw new Error("Расшифрованные данные имеют некорректный формат.");
  }
}

export async function generateSteamGuardCode(sharedSecret, timestampMs = Date.now()) {
  requireWebCrypto();
  const secretBytes = decodeBase64(sharedSecret);
  if (secretBytes.length < 16 || secretBytes.length > 128) {
    secretBytes.fill(0);
    throw new Error("Некорректная длина shared_secret.");
  }

  const unixSeconds = Math.floor(timestampMs / 1000);
  const counter = Math.floor(unixSeconds / 30);
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000), false);
  view.setUint32(4, counter >>> 0, false);

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  secretBytes.fill(0);

  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, counterBytes));
  const offset = digest[19] & 0x0f;
  let fullCode =
    (digest[offset] & 0x7f) * 0x1_000000 +
    digest[offset + 1] * 0x1_0000 +
    digest[offset + 2] * 0x100 +
    digest[offset + 3];

  let code = "";
  for (let index = 0; index < 5; index += 1) {
    code += STEAM_CODE_ALPHABET[fullCode % STEAM_CODE_ALPHABET.length];
    fullCode = Math.floor(fullCode / STEAM_CODE_ALPHABET.length);
  }
  digest.fill(0);
  return code;
}

export function steamCodeWindow(timestampMs = Date.now()) {
  const seconds = timestampMs / 1000;
  const position = ((seconds % 30) + 30) % 30;
  const remainingPrecise = 30 - position;
  return {
    step: Math.floor(seconds / 30),
    secondsRemaining: Math.max(1, Math.ceil(remainingPrecise)),
    remainingFraction: Math.min(1, Math.max(0, remainingPrecise / 30)),
  };
}
