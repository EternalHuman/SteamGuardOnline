# SGO (SteamGuardOnline) - Cloudflare Pages

Сайт проекта: <https://steamguard.cloud/>

Готовый open-source сайт, работающий как online Steam Guard Authenticator. Пользователь загружает один или несколько обычных JSON `maFile`, получает для каждого случайный ID длиной ровно 16 символов и затем может открывать Steam Guard-коды с другого устройства. Дополнительно можно привязать собственный код от 3 символов, например `aB1`, при одиночной загрузке или после входа по основному ID.

Исходный код проекта: <https://github.com/EternalHuman/SteamGuardOnline>

> **Важно:** проект не связан с Valve Corporation или Steam. Размещение второго фактора онлайн уменьшает физическое разделение факторов. Для максимальной безопасности рекомендуется официальное мобильное приложение Steam.

## Что реализовано

- Cloudflare Pages + Pages Functions без фреймворка и без build-этапа.
- Cloudflare Workers KV для хранения зашифрованных записей.
- Основной случайный ID: ровно 16 символов, без неоднозначных `0/O/1/I/l`.
- Пользовательский альтернативный код: 3–64 ASCII-символа.
- Смена языка интерфейса: English, 简体中文, Русский, Español, Português BR.
- Загрузка нескольких maFile за один импорт с отдельным ID для каждого аккаунта.
- Автодобавление созданных ID в сохранённые профили; cookie хранит их без срока окончания.
- Optional PIN для сохранённых профилей: с PIN access ID хранится в KV в PIN-зашифрованном виде, без PIN защита зависит от cookie устройства.
- Генерация актуального пятисимвольного Steam Guard-кода каждые 30 секунд.
- Привязка, замена и удаление пользовательского кода.
- Удаление всего хранилища из KV по основному ID.
- Rate limiting на уровне API с короткоживущими KV-счётчиками.
- CSP, запрет iframe, `no-store` для API, отсутствие сторонних скриптов и шрифтов.
- Адаптивный интерфейс для компьютеров и телефонов.

## Модель хранения

Полный `maFile` **никогда не отправляется** в Pages Function.

1. Браузер читает JSON локально.
2. Из файла извлекаются только `shared_secret` и, по выбору пользователя, `account_name`.
3. `identity_secret`, Steam session, revocation code, device data и остальные поля отбрасываются.
4. Минимальный payload шифруется случайным ключом AES-256-GCM.
5. Для каждого кода доступа браузер локально выполняет PBKDF2-SHA-256, формирует непрозрачный lookup token и шифрует ключ данных.
6. В KV отправляются только ciphertext, обёрнутый ключ и lookup token.
7. При следующем входе расшифровка и генерация Steam Guard-кода происходят в браузере.

Код доступа можно передать при открытии сайта через `?id=<code>`. После чтения параметр очищается из адресной строки. Если включено запоминание профиля, cookie браузера хранит ссылку на профиль без срока окончания. При включённом PIN основной ID или пользовательский код хранится в KV в PIN-зашифрованном виде; при отключённом PIN в cookie хранится device secret, поэтому украденная cookie сможет открыть профиль. API-запросы отправляются без cookies.

## Поддерживаемые maFile

Поддерживается обычный JSON maFile с полем:

```json
{
  "shared_secret": "base64-value",
  "account_name": "optional-name"
}
```

Зашифрованные SDA maFile, в которых `shared_secret` недоступен без локального пароля шифрования, не поддерживаются. Сайт не запрашивает ни этот пароль, ни логин/пароль Steam.

## Deploy через GitHub → Cloudflare Pages

### 1. Загрузите проект в GitHub

Распакуйте архив и загрузите содержимое папки в корень репозитория. В корне должны находиться директории `public` и `functions`.

### 2. Создайте KV namespace

В Cloudflare Dashboard откройте **Workers & Pages → KV** и создайте namespace, например:

```text
sda-vault
```

### 3. Создайте Pages project

1. Откройте **Workers & Pages → Create application → Pages → Connect to Git**.
2. Выберите GitHub-репозиторий.
3. Framework preset: **None**.
4. Build command: оставьте пустым или укажите `exit 0`.
5. Build output directory: `public`.
6. Root directory: корень репозитория.
7. Выполните первый deploy.

### 4. Добавьте KV binding

В Pages project откройте **Settings → Bindings → Add → KV namespace**:

```text
Variable name: SDA_KV
KV namespace: sda-vault
```

Добавьте binding как минимум для Production. Для Preview deployments используйте отдельный namespace либо тот же namespace осознанно.

После добавления binding выполните **Redeploy** последнего deployment.

### 5. Опциональный срок хранения

В **Settings → Variables and Secrets** можно добавить обычную переменную:

```text
SDA_TTL_DAYS=365
```

Тогда новые записи и access indexes будут автоматически удаляться через указанное число дней. Если переменная отсутствует или равна `0`, срок хранения не ограничивается приложением.

## Локальный запуск

Требуется современный Node.js.

```bash
npm run dev
```

Команда использует локальное KV-хранилище Wrangler и запускает Pages на локальном адресе. Для сохранения локальных KV-данных между запусками можно добавить стандартные параметры persistence Wrangler.

Проверка криптографического цикла и Steam Guard test vectors:

```bash
npm test
```

Ручной deploy через Wrangler:

```bash
npm run deploy
```

При CLI deploy заранее создайте KV namespace и настройте binding через Cloudflare Dashboard либо используйте собственный `wrangler.toml`, взяв за основу `wrangler.toml.example`.

## Структура проекта

```text
.
├── functions/
│   └── api/
│       └── [[path]].js       # import, lookup, alias, delete, saved profiles, health
├── public/
│   ├── _headers              # CSP и security headers
│   ├── _routes.json          # Functions вызываются только для /api/*
│   ├── app.js                # интерфейс и клиентский workflow
│   ├── crypto.js             # PBKDF2, HKDF, AES-GCM, Steam Guard
│   ├── favicon.svg
│   ├── index.html
│   └── styles.css
├── tests/
│   └── crypto.test.mjs
├── SECURITY.md
└── package.json
```

## API

Все изменяющие запросы - same-origin `POST application/json`. Клиент отправляет их без cookies. Saved profiles открываются через opaque profile id и verifier; открытый PIN и access ID в API не передаются.

- `GET /api/health`
- `POST /api/import`
- `POST /api/lookup`
- `POST /api/alias`
- `POST /api/delete`
- `POST /api/save-saved`
- `POST /api/open-saved`
- `POST /api/delete-saved`

Ответы API имеют `Cache-Control: no-store`.

## Важные ограничения

### Eventual consistency Workers KV

Workers KV является eventually consistent. После создания записи, смены alias или удаления старый/новый индекс в другом регионе Cloudflare может стать видимым с задержкой. Интерфейс сообщает пользователю повторить запрос позже. Для строгой глобальной уникальности alias и немедленного отзыва доступа следует заменить операции индексов на Durable Object или другую strongly consistent storage.

### Доверие к deployment

Client-side encryption защищает содержимое KV, но владелец deployment теоретически способен изменить JavaScript и собрать секрет при следующем посещении. Пользователь должен доверять конкретному deployment, проверять исходный код и защищать GitHub/Cloudflare аккаунты владельца.

### Секретный ID - bearer credential

Любой, кто знает основной ID или пользовательский код, способен получить Steam Guard-коды. Не передавайте их третьим лицам. Интерфейс разрешает пользовательские коды от 3 символов, но короткий или популярный код можно подобрать; лучше использовать длинный и уникальный секрет.

### Cookie с профилями

Опция запоминания хранит профиль в cookie браузера без срока окончания. PIN 3–6 символов включён по умолчанию, но его можно отключить. С PIN cookie хранит opaque profile id и соль, а основной ID или пользовательский код хранится в KV в PIN-зашифрованном виде. Без PIN cookie дополнительно хранит device secret, поэтому кража cookie достаточна для открытия профиля.

После 5 неверных PIN-попыток API удаляет соответствующее хранилище из KV и saved profile запись. Cookie-строка профиля также удаляется из браузера.

PIN защищает cookie от прямого использования в интерфейсе, но короткий PIN не является полноценной заменой защите устройства и браузера. Отключение PIN снижает безопасность и оставлено только для удобства.

### Часы устройства

Steam Guard зависит от времени. На устройстве должна быть включена автоматическая синхронизация даты и времени.

## Лицензия

MIT. См. `LICENSE`.
