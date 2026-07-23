const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store, max-age=0",
  pragma: "no-cache",
  "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "strict-transport-security": "max-age=31536000",
};

const ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SAVED_PROFILE_ID_PATTERN = /^[A-Za-z0-9_-]{24,64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_REQUEST_BYTES = 24_000;
const IMPORT_RATE_LIMIT = 50;
const SAVE_SAVED_PROFILE_RATE_LIMIT = 50;
const SAVED_PROFILE_MAX_PIN_ATTEMPTS = 5;

class ApiError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.headers = headers;
  }
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

function emptyResponse(status = 204, extraHeaders = {}) {
  return new Response(null, {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

async function indexHtmlResponse(context) {
  if (!context.env?.ASSETS || typeof context.env.ASSETS.fetch !== "function") {
    throw new ApiError(404, "Страница не найдена.");
  }

  const url = new URL(context.request.url);
  url.pathname = "/index.html";
  url.search = "";

  return context.env.ASSETS.fetch(
    new Request(url.toString(), {
      method: "GET",
      headers: context.request.headers,
    }),
  );
}

function assertConfigured(env) {
  if (!env.SDA_KV || typeof env.SDA_KV.get !== "function") {
    throw new ApiError(503, "KV binding SDA_KV не настроен.");
  }
}

function assertSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return;

  const expectedOrigin = new URL(request.url).origin;
  if (origin !== expectedOrigin) {
    throw new ApiError(403, "Запрос с другого origin отклонён.");
  }
}

async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ApiError(415, "Ожидается Content-Type: application/json.");
  }

  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "Запрос слишком большой.");
  }

  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "Запрос слишком большой.");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, "Некорректный JSON.");
  }
}

function validateToken(token, fieldName = "token") {
  if (typeof token !== "string" || !ACCESS_TOKEN_PATTERN.test(token)) {
    throw new ApiError(400, `Поле ${fieldName} имеет некорректный формат.`);
  }
  return token;
}

function validateSavedProfileId(value, fieldName = "id") {
  if (typeof value !== "string" || !SAVED_PROFILE_ID_PATTERN.test(value)) {
    throw new ApiError(400, `Поле ${fieldName} имеет некорректный формат.`);
  }
  return value;
}

function validateBase64Url(value, fieldName, minLength, maxLength) {
  if (
    typeof value !== "string" ||
    value.length < minLength ||
    value.length > maxLength ||
    !BASE64URL_PATTERN.test(value)
  ) {
    throw new ApiError(400, `Поле ${fieldName} имеет некорректный формат.`);
  }
  return value;
}

function validateWrap(wrap) {
  if (!wrap || typeof wrap !== "object" || Array.isArray(wrap) || wrap.v !== 1) {
    throw new ApiError(400, "Некорректная структура обёрнутого ключа.");
  }

  return {
    v: 1,
    salt: validateBase64Url(wrap.salt, "wrap.salt", 22, 22),
    iv: validateBase64Url(wrap.iv, "wrap.iv", 16, 16),
    ciphertext: validateBase64Url(wrap.ciphertext, "wrap.ciphertext", 64, 64),
  };
}

function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || payload.v !== 1) {
    throw new ApiError(400, "Некорректная структура зашифрованных данных.");
  }

  return {
    v: 1,
    iv: validateBase64Url(payload.iv, "payload.iv", 16, 16),
    ciphertext: validateBase64Url(payload.ciphertext, "payload.ciphertext", 24, 12_000),
  };
}

function validateAccessEntry(value, fieldName) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, `Поле ${fieldName} отсутствует.`);
  }
  return {
    token: validateToken(value.token, `${fieldName}.token`),
    wrap: validateWrap(value.wrap),
  };
}

function validateSavedProfileEncrypted(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.v !== 1) {
    throw new ApiError(400, "Некорректная структура сохранённого профиля.");
  }

  return {
    v: 1,
    salt: validateBase64Url(value.salt, "encrypted.salt", 22, 22),
    iv: validateBase64Url(value.iv, "encrypted.iv", 16, 16),
    ciphertext: validateBase64Url(value.ciphertext, "encrypted.ciphertext", 24, 160),
  };
}

function accessKey(token) {
  return `access:${token}`;
}

function recordKey(recordId) {
  return `record:${recordId}`;
}

function savedProfileKey(profileId) {
  return `saved-profile:${profileId}`;
}

function toBase64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomId() {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(18)));
}

async function sha256Base64Url(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return toBase64Url(digest);
}

function expirationOptions(env) {
  const days = Number(env.SDA_TTL_DAYS || 0);
  if (!Number.isFinite(days) || days < 1) return undefined;
  const safeDays = Math.min(Math.floor(days), 3650);
  return { expirationTtl: safeDays * 86_400 };
}

async function getJson(kv, key) {
  const raw = await kv.get(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw);
  } catch {
    throw new ApiError(500, "Хранилище содержит повреждённую запись.");
  }
}

async function putJson(kv, key, value, options) {
  const serialized = JSON.stringify(value);
  if (options) {
    await kv.put(key, serialized, options);
  } else {
    await kv.put(key, serialized);
  }
}

async function enforceRateLimit(env, request, scope, limit) {
  const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
  const minute = Math.floor(Date.now() / 60_000);
  const ipHash = await sha256Base64Url(`sda-rate-v1\0${ip}`);
  const key = `rate:${scope}:${minute}:${ipHash.slice(0, 32)}`;
  const current = Number((await env.SDA_KV.get(key)) || 0);

  if (Number.isFinite(current) && current >= limit) {
    throw new ApiError(429, "Слишком много запросов. Повторите попытку позже.", { "retry-after": "60" });
  }

  await env.SDA_KV.put(key, String((Number.isFinite(current) ? current : 0) + 1), { expirationTtl: 120 });
}

async function handleImport(context) {
  await enforceRateLimit(context.env, context.request, "import", IMPORT_RATE_LIMIT);
  const body = await readJson(context.request);
  const primary = validateAccessEntry(body.primary, "primary");
  const alias = body.alias == null ? null : validateAccessEntry(body.alias, "alias");
  const payload = validatePayload(body.payload);

  if (alias && alias.token === primary.token) {
    throw new ApiError(400, "Основной и пользовательский коды должны отличаться.");
  }

  const [primaryExists, aliasExists] = await Promise.all([
    context.env.SDA_KV.get(accessKey(primary.token)),
    alias ? context.env.SDA_KV.get(accessKey(alias.token)) : Promise.resolve(null),
  ]);

  if (primaryExists !== null) {
    throw new ApiError(409, "Сгенерированный ID уже занят. Повторите импорт.");
  }
  if (alias && aliasExists !== null) {
    throw new ApiError(409, "Пользовательский код уже занят.");
  }

  const now = new Date().toISOString();
  const recordId = randomId();
  const record = {
    v: 1,
    payload,
    primaryToken: primary.token,
    aliasToken: alias?.token || null,
    createdAt: now,
    updatedAt: now,
  };
  const options = expirationOptions(context.env);
  const createdKeys = [];

  try {
    await putJson(context.env.SDA_KV, recordKey(recordId), record, options);
    createdKeys.push(recordKey(recordId));

    await putJson(
      context.env.SDA_KV,
      accessKey(primary.token),
      { v: 1, recordId, kind: "primary", wrap: primary.wrap, createdAt: now },
      options,
    );
    createdKeys.push(accessKey(primary.token));

    if (alias) {
      await putJson(
        context.env.SDA_KV,
        accessKey(alias.token),
        { v: 1, recordId, kind: "alias", wrap: alias.wrap, createdAt: now },
        options,
      );
      createdKeys.push(accessKey(alias.token));
    }
  } catch (error) {
    await Promise.allSettled(createdKeys.map((key) => context.env.SDA_KV.delete(key)));
    throw error;
  }

  return jsonResponse({ ok: true, recordId, createdAt: now, aliasAttached: Boolean(alias) }, 201);
}

async function handleLookup(context) {
  await enforceRateLimit(context.env, context.request, "lookup", 20);
  const body = await readJson(context.request);
  const token = validateToken(body.token);
  const entry = await getJson(context.env.SDA_KV, accessKey(token));

  if (!entry || entry.v !== 1 || (entry.kind !== "primary" && entry.kind !== "alias")) {
    throw new ApiError(404, "Хранилище не найдено. Проверьте секретный код.");
  }

  const record = await getJson(context.env.SDA_KV, recordKey(entry.recordId));
  if (!record || record.v !== 1) {
    throw new ApiError(503, "Запись ещё реплицируется или была удалена. Повторите попытку чуть позже.");
  }

  return jsonResponse({
    ok: true,
    kind: entry.kind,
    recordId: entry.recordId,
    wrap: validateWrap(entry.wrap),
    payload: validatePayload(record.payload),
    createdAt: record.createdAt,
    hasAlias: Boolean(record.aliasToken),
  });
}

async function requirePrimaryRecord(env, primaryToken) {
  const token = validateToken(primaryToken, "primaryToken");
  const entry = await getJson(env.SDA_KV, accessKey(token));
  if (!entry || entry.v !== 1 || entry.kind !== "primary") {
    throw new ApiError(403, "Для управления требуется основной ID.");
  }

  const record = await getJson(env.SDA_KV, recordKey(entry.recordId));
  if (!record || record.v !== 1 || record.primaryToken !== token) {
    throw new ApiError(404, "Хранилище не найдено.");
  }
  return { token, entry, record };
}

async function deleteVaultByAccessToken(env, accessToken) {
  const token = validateToken(accessToken, "accessToken");
  const entry = await getJson(env.SDA_KV, accessKey(token));
  if (!entry || entry.v !== 1) return false;

  const record = await getJson(env.SDA_KV, recordKey(entry.recordId));
  if (!record || record.v !== 1) {
    await env.SDA_KV.delete(accessKey(token));
    return false;
  }

  const keys = [recordKey(entry.recordId), accessKey(record.primaryToken)];
  if (record.aliasToken) keys.push(accessKey(record.aliasToken));
  if (!keys.includes(accessKey(token))) keys.push(accessKey(token));
  await Promise.all(keys.map((key) => env.SDA_KV.delete(key)));
  return true;
}

async function handleAlias(context) {
  await enforceRateLimit(context.env, context.request, "alias", 8);
  const body = await readJson(context.request);
  const { token: primaryToken, entry, record } = await requirePrimaryRecord(context.env, body.primaryToken);
  const now = new Date().toISOString();
  const options = expirationOptions(context.env);

  if (body.remove === true) {
    const oldAliasToken = record.aliasToken;
    record.aliasToken = null;
    record.updatedAt = now;
    await Promise.all([
      putJson(context.env.SDA_KV, recordKey(entry.recordId), record, options),
      putJson(context.env.SDA_KV, accessKey(primaryToken), entry, options),
    ]);
    if (oldAliasToken) {
      await context.env.SDA_KV.delete(accessKey(oldAliasToken));
    }
    return jsonResponse({ ok: true, aliasAttached: false });
  }

  const alias = validateAccessEntry(body.alias, "alias");
  if (alias.token === primaryToken) {
    throw new ApiError(400, "Пользовательский код должен отличаться от основного ID.");
  }

  const existing = await getJson(context.env.SDA_KV, accessKey(alias.token));
  if (existing && existing.recordId !== entry.recordId) {
    throw new ApiError(409, "Пользовательский код уже занят.");
  }

  const oldAliasToken = record.aliasToken;
  await putJson(
    context.env.SDA_KV,
    accessKey(alias.token),
    { v: 1, recordId: entry.recordId, kind: "alias", wrap: alias.wrap, createdAt: existing?.createdAt || now },
    options,
  );

  record.aliasToken = alias.token;
  record.updatedAt = now;
  await Promise.all([
    putJson(context.env.SDA_KV, recordKey(entry.recordId), record, options),
    putJson(context.env.SDA_KV, accessKey(primaryToken), entry, options),
  ]);

  if (oldAliasToken && oldAliasToken !== alias.token) {
    await context.env.SDA_KV.delete(accessKey(oldAliasToken));
  }

  return jsonResponse({ ok: true, aliasAttached: true });
}

async function handleDelete(context) {
  await enforceRateLimit(context.env, context.request, "delete", 5);
  const body = await readJson(context.request);
  const { token } = await requirePrimaryRecord(context.env, body.primaryToken);

  await deleteVaultByAccessToken(context.env, token);

  return jsonResponse({ ok: true, deleted: true });
}

async function handleSaveSaved(context) {
  await enforceRateLimit(context.env, context.request, "save-saved", SAVE_SAVED_PROFILE_RATE_LIMIT);
  const body = await readJson(context.request);
  const id = validateSavedProfileId(body.id);
  const accessToken = validateToken(body.accessToken, "accessToken");
  const verifier = validateToken(body.verifier, "verifier");
  const encrypted = validateSavedProfileEncrypted(body.encrypted);
  const accessEntry = await getJson(context.env.SDA_KV, accessKey(accessToken));

  if (!accessEntry || accessEntry.v !== 1) {
    throw new ApiError(404, "Хранилище не найдено. Проверьте секретный код.");
  }

  const key = savedProfileKey(id);
  const existing = await getJson(context.env.SDA_KV, key);
  if (existing && existing.v === 1 && existing.accessToken !== accessToken) {
    throw new ApiError(409, "Сохранённый профиль уже существует.");
  }

  const now = new Date().toISOString();
  await putJson(
    context.env.SDA_KV,
    key,
    {
      v: 1,
      accessToken,
      verifier,
      encrypted,
      attempts: 0,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    },
    expirationOptions(context.env),
  );

  return jsonResponse({ ok: true, saved: true });
}

async function handleOpenSaved(context) {
  await enforceRateLimit(context.env, context.request, "open-saved", 10);
  const body = await readJson(context.request);
  const id = validateSavedProfileId(body.id);
  const verifier = validateToken(body.verifier, "verifier");
  const key = savedProfileKey(id);
  const profile = await getJson(context.env.SDA_KV, key);

  if (!profile || profile.v !== 1) {
    throw new ApiError(404, "Сохранённый профиль не найден.");
  }

  if (profile.verifier !== verifier) {
    const attempts = Math.min(
      SAVED_PROFILE_MAX_PIN_ATTEMPTS,
      Math.max(0, Number(profile.attempts) || 0) + 1,
    );

    if (attempts >= SAVED_PROFILE_MAX_PIN_ATTEMPTS) {
      await deleteVaultByAccessToken(context.env, profile.accessToken);
      await context.env.SDA_KV.delete(key);
      return jsonResponse(
        {
          ok: false,
          error: "PIN введён неверно 5 раз. Хранилище удалено из KV.",
          deleted: true,
          attemptsLeft: 0,
        },
        403,
      );
    }

    await putJson(
      context.env.SDA_KV,
      key,
      { ...profile, attempts, updatedAt: new Date().toISOString() },
      expirationOptions(context.env),
    );
    return jsonResponse(
      {
        ok: false,
        error: "Неверный PIN.",
        deleted: false,
        attemptsLeft: SAVED_PROFILE_MAX_PIN_ATTEMPTS - attempts,
      },
      403,
    );
  }

  const accessEntry = await getJson(context.env.SDA_KV, accessKey(profile.accessToken));
  if (!accessEntry || accessEntry.v !== 1) {
    await context.env.SDA_KV.delete(key);
    throw new ApiError(404, "Хранилище не найдено. Проверьте секретный код.");
  }

  if (Number(profile.attempts) > 0) {
    await putJson(
      context.env.SDA_KV,
      key,
      { ...profile, attempts: 0, updatedAt: new Date().toISOString() },
      expirationOptions(context.env),
    );
  }

  return jsonResponse({
    ok: true,
    encrypted: validateSavedProfileEncrypted(profile.encrypted),
    attemptsLeft: SAVED_PROFILE_MAX_PIN_ATTEMPTS,
  });
}

async function handleDeleteSaved(context) {
  await enforceRateLimit(context.env, context.request, "delete-saved", 5);
  const body = await readJson(context.request);
  const id = validateSavedProfileId(body.id);
  const key = savedProfileKey(id);
  const profile = await getJson(context.env.SDA_KV, key);
  if (!profile || profile.v !== 1) {
    return jsonResponse({ ok: true, deleted: false });
  }

  const deleted = await deleteVaultByAccessToken(context.env, profile.accessToken);
  await context.env.SDA_KV.delete(key);

  return jsonResponse({ ok: true, deleted });
}

async function routeRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");

  if (request.method === "GET" && route === "") {
    return indexHtmlResponse(context);
  }

  assertConfigured(context.env);

  if (request.method === "OPTIONS") {
    return emptyResponse(204, { allow: "GET, POST, OPTIONS" });
  }

  if (request.method === "GET" && route === "health") {
    return jsonResponse({ ok: true, service: "sda-cloudflare-pages", version: 1 });
  }

  if (request.method !== "POST") {
    throw new ApiError(405, "Метод не поддерживается.", { allow: "GET, POST, OPTIONS" });
  }

  assertSameOrigin(request);

  switch (route) {
    case "import":
      return handleImport(context);
    case "lookup":
      return handleLookup(context);
    case "alias":
      return handleAlias(context);
    case "delete":
      return handleDelete(context);
    case "save-saved":
      return handleSaveSaved(context);
    case "open-saved":
      return handleOpenSaved(context);
    case "delete-saved":
      return handleDeleteSaved(context);
    default:
      throw new ApiError(404, "API endpoint не найден.");
  }
}

export async function onRequest(context) {
  try {
    return await routeRequest(context);
  } catch (error) {
    if (error instanceof ApiError) {
      return jsonResponse({ ok: false, error: error.message }, error.status, error.headers);
    }

    console.error("Unhandled SDA API error", error);
    return jsonResponse({ ok: false, error: "Внутренняя ошибка сервера." }, 500);
  }
}
