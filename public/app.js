import {
  ALIAS_MAX_LENGTH,
  ALIAS_MIN_LENGTH,
  createAccessEnvelope,
  createEncryptedPayload,
  decryptEncryptedPayload,
  disposePreparedAccess,
  fromBase64Url,
  generateSteamGuardCode,
  isPrimaryCode,
  normalizeAccessCode,
  prepareAccessCode,
  randomBytes,
  randomPrimaryCode,
  steamCodeWindow,
  toBase64Url,
  unwrapDataKeyWithPreparedAccess,
  validateAccessCode,
  validateAlias,
  validateSharedSecret,
} from "./crypto.js";

const elements = {
  languageSelect: document.querySelector("#language-select"),
  homeSections: [...document.querySelectorAll("[data-home-section]")],
  vaultModeButtons: [...document.querySelectorAll("[data-vault-mode]")],
  vaultModePanels: [...document.querySelectorAll("[data-vault-panel]")],
  siteTabButtons: [...document.querySelectorAll("[data-site-tab]")],
  siteInfoPanels: document.querySelector("#site-info-panels"),
  siteTabPanels: [...document.querySelectorAll("[data-site-panel]")],
  flowToggle: document.querySelector("#flow-toggle"),
  flowDetailsPanel: document.querySelector("#flow-details-panel"),
  accessForm: document.querySelector("#access-form"),
  accessCode: document.querySelector("#access-code"),
  accessSubmit: document.querySelector("#access-submit"),
  accessStatus: document.querySelector("#access-status"),
  accessVisibility: document.querySelector("#access-visibility"),
  savedProfiles: document.querySelector("#saved-profiles"),
  savedProfileList: document.querySelector("#saved-profile-list"),
  savedProfilePinPanel: document.querySelector("#saved-profile-pin-panel"),
  savedProfilePinTitle: document.querySelector("#saved-profile-pin-title"),
  savedProfilePin: document.querySelector("#saved-profile-pin"),
  savedProfilePinSubmit: document.querySelector("#saved-profile-pin-submit"),
  savedProfilePinCancel: document.querySelector("#saved-profile-pin-cancel"),
  savedProfileStatus: document.querySelector("#saved-profile-status"),
  clearProfiles: document.querySelector("#clear-profiles"),
  importForm: document.querySelector("#import-form"),
  maFileInput: document.querySelector("#mafile-input"),
  fileDrop: document.querySelector("#file-drop"),
  selectedFile: document.querySelector("#selected-file"),
  customAlias: document.querySelector("#custom-alias"),
  customAliasVisibility: document.querySelector("#custom-alias-visibility"),
  aliasHint: document.querySelector("#alias-hint"),
  keepLabel: document.querySelector("#keep-label"),
  rememberImportedPinEnabled: document.querySelector("#remember-imported-pin-enabled"),
  rememberImportedPinField: document.querySelector("#remember-imported-pin-field"),
  rememberImportedPin: document.querySelector("#remember-imported-pin"),
  rememberImportedPinWarning: document.querySelector("#remember-imported-pin-warning"),
  importSubmit: document.querySelector("#import-submit"),
  importStatus: document.querySelector("#import-status"),
  importResult: document.querySelector("#import-result"),
  importResultList: document.querySelector("#import-result-list"),
  authPanel: document.querySelector("#auth-panel"),
  accountLabel: document.querySelector("#account-label"),
  accessKindBadge: document.querySelector("#access-kind-badge"),
  guardCode: document.querySelector("#guard-code"),
  countdownValue: document.querySelector("#countdown-value"),
  countdownCircle: document.querySelector("#countdown-circle"),
  copyGuard: document.querySelector("#copy-guard"),
  logoutButton: document.querySelector("#logout-button"),
  managePrimary: document.querySelector("#manage-primary"),
  manageAliasOnly: document.querySelector("#manage-alias-only"),
  aliasForm: document.querySelector("#alias-form"),
  newAlias: document.querySelector("#new-alias"),
  aliasSubmit: document.querySelector("#alias-submit"),
  aliasStatus: document.querySelector("#manage-alias-status"),
  removeAlias: document.querySelector("#remove-alias"),
  deleteVault: document.querySelector("#delete-vault"),
  serviceStatus: document.querySelector("#service-status"),
  toast: document.querySelector("#toast"),
  year: document.querySelector("#year"),
};

const DEFAULT_LANGUAGE = "ru";
const LANGUAGE_STORAGE_KEY = "sda-vault-language";
const PROFILE_STORAGE_KEY = "sgo_saved_profiles_v1";
const PROFILE_COOKIE_NAME = "sgo_saved_profiles_v1";
const PROFILE_COOKIE_CHUNK_PREFIX = `${PROFILE_COOKIE_NAME}_chunk_`;
const PROFILE_COOKIE_CHUNK_COUNT_NAME = `${PROFILE_COOKIE_NAME}_chunk_count`;
const PROFILE_COOKIE_EXPIRES = "Fri, 31 Dec 9999 23:59:59 GMT";
const PROFILE_COOKIE_MAX_BYTES = 3500;
const PROFILE_COOKIE_MAX_CHUNKS = 20;
const IMPORT_FILE_LIMIT = 50;
const SAVED_PROFILE_LIMIT = 50;
const SAVED_PROFILE_MAX_PIN_ATTEMPTS = 5;
const SAVED_PROFILE_ID_BYTES = 18;
const SAVED_PROFILE_DEVICE_SECRET_BYTES = 32;
const SAVED_PROFILE_RECORD_ID_LENGTH = 24;
const PIN_KDF_ITERATIONS = 260_000;
const PROFILE_PIN_SALT_PREFIX = "SGO saved profile PIN v1";
const PROFILE_PIN_AAD = new TextEncoder().encode("SGO saved profile access code v1");
const PROFILE_PIN_VERIFIER_CONTEXT = new TextEncoder().encode("SGO saved profile PIN verifier v1");
const LANGUAGE_META = {
  en: { htmlLang: "en" },
  "zh-CN": { htmlLang: "zh-CN" },
  ru: { htmlLang: "ru" },
  es: { htmlLang: "es" },
  "pt-BR": { htmlLang: "pt-BR" },
};
const INFO_PAGE_BY_PATH = new Map([
  ["/api", "api"],
]);

const TRANSLATIONS = {
  ru: {
    "meta.title": "SGO (SteamGuardOnline) — Online Steam Desktop Authenticator",
    "meta.description":
      "Open-source online Steam Desktop Authenticator для безопасного получения Steam Guard-кодов по секретному ID без логина и пароля Steam.",
    "language.label": "Язык",
    "language.aria": "Язык сайта",
    "brand.homeAria": "SGO (SteamGuardOnline) — на главную",
    "header.projectLinksAria": "Ссылки проекта",
    "header.infoTabsAria": "Информационные разделы",
    "service.checking": "Проверка API…",
    "service.ready": "API и KV готовы",
    "service.warning": "Требуется настройка KV",
    "hero.eyebrow": "<span></span> Online Steam Desktop Authenticator",
    "hero.title": "Steam Guard-коды<br /><em>на любом устройстве</em>",
    "hero.lead":
      "Загрузите maFile один раз, сохраните 16-символьный ID и открывайте актуальный код Steam Guard с другого компьютера или телефона. Логин и пароль Steam не нужны.",
    "hero.pointsAria": "Основные свойства",
    "hero.point.encrypt": "maFile шифруется в браузере",
    "hero.point.noUrl": "Параметр id очищается из URL после чтения",
    "hero.point.noScripts": "Без сторонних скриптов",
    "vault.kicker": "Зашифрованное хранилище",
    "vault.title": "Открыть или создать SGO",
    "vault.modeAria": "Режим работы",
    "vault.tab.access": "Получить код",
    "vault.tab.import": "Загрузить maFile",
    "vault.tab.security": "Безопасность",
    "vault.tab.api": "API",
    "access.panelAria": "Открытие хранилища",
    "access.label": "Основной ID или пользовательский код",
    "access.placeholder": "Например: super_secret_code123",
    "access.help": "Код преобразуется в криптографический token локально. Если сохранённый профиль защищён PIN, сайт запросит PIN перед открытием.",
    "access.submit": "Открыть authenticator",
    "access.openSuccess": "Хранилище расшифровано локально в браузере.",
    "access.openError": "Не удалось открыть хранилище.",
    "profiles.title": "Сохранённые профили",
    "profiles.empty": "Сохранённых профилей пока нет.",
    "profiles.open": "Открыть",
    "profiles.remove": "Удалить",
    "profiles.clear": "Очистить",
    "profiles.clearConfirm": "Удалить все сохранённые профили из хранилища этого браузера?",
    "profiles.rememberTitle": "Запомнить профиль на этом устройстве",
    "profiles.rememberHelp": "Профиль сохранится в хранилище этого браузера без срока окончания. PIN-защищённые профили запросят PIN при открытии.",
    "profiles.pinEnabledTitle": "Защитить сохранённый профиль PIN-кодом",
    "profiles.pinEnabledHelp": "Если PIN выключен, доступ к хранилищу браузера сможет открыть профиль без дополнительного секрета.",
    "profiles.pinLabel": "PIN-код профиля",
    "profiles.pinPlaceholder": "3–6",
    "profiles.pinHelp": "PIN необязателен, но с ним сохранённый профиль защищён от прямого использования данных браузерного хранилища. 5 неверных попыток удалят хранилище из KV.",
    "profiles.pinUnlockTitle": "Введите PIN для {label}",
    "profiles.pinUnlockHelp": "5 неверных попыток удалят связанное хранилище из KV.",
    "profiles.pinDisabledWarning": "PIN-защита выключена. Уровень безопасности ниже: при доступе к хранилищу браузера профиль можно будет открыть без PIN.",
    "profiles.pinInvalid": "Введите PIN от 3 до 6 печатных символов.",
    "profiles.rememberImportedTitle": "Добавить созданные ID в профили",
    "profiles.rememberImportedHelp": "После импорта они появятся во вкладке получения кода.",
    "profiles.cookieHelp": "С PIN браузер хранит ссылку на профиль и соль, а access ID остаётся в KV в PIN-зашифрованном виде. Без PIN браузер хранит device secret. 5 неверных PIN-попыток удалят хранилище из KV.",
    "profiles.kind.primary": "Основной ID",
    "profiles.kind.alias": "Пользовательский код",
    "profiles.pinProtected": "PIN",
    "profiles.noPin": "без PIN",
    "profiles.noPinShort": "без PIN",
    "profiles.deviceSecretMissing": "Профиль без PIN повреждён или создан в другом браузере.",
    "profiles.saved": "Профиль сохранён на этом устройстве.",
    "profiles.savedCount": "Сохранено профилей: {count}.",
    "profiles.removed": "Профиль удалён.",
    "profiles.cleared": "Сохранённые профили очищены.",
    "profiles.saveError": "Не удалось сохранить профиль.",
    "profiles.attemptsLeft": "осталось {count}",
    "profiles.pinWrong": "Неверный PIN.",
    "profiles.pinWrongWithAttempts": "Неверный PIN. Осталось попыток: {count}. После 5 неверных попыток хранилище будет удалено из KV.",
    "profiles.deletedAfterAttempts": "PIN введён неверно 5 раз. Хранилище удалено из KV, профиль удалён из браузера.",
    "profiles.deleteAfterAttemptsError": "Не удалось удалить хранилище после 5 неверных PIN-попыток.",
    "accessKind.primary": "Основной ID",
    "accessKind.alias": "Пользовательский код",
    "action.show": "Показать",
    "action.hide": "Скрыть",
    "action.copy": "Копировать",
    "action.cancel": "Отмена",
    "busy.processing": "Обработка…",
    "busy.decrypting": "Расшифровка…",
    "busy.encrypting": "Шифрование…",
    "busy.binding": "Привязка…",
    "toast.copied": "Скопировано",
    "copy.primary": "Основной ID скопирован",
    "copy.alias": "Пользовательский код скопирован",
    "copy.guard": "Steam Guard-код скопирован",
    "import.panelAria": "Импорт maFile",
    "import.noFile": "Файлы не выбраны",
    "import.dropTitle": "Перетащите maFile сюда",
    "import.dropSubtitle": "или нажмите, чтобы выбрать один или несколько файлов",
    "import.aliasLabelHtml": "Свой код доступа <span>необязательно</span>",
    "import.aliasPlaceholder": "super_secret_code123",
    "import.keepLabelTitle": "Сохранить имя аккаунта",
    "import.keepLabelHelp": "Имя попадёт только внутрь зашифрованного контейнера.",
    "import.security":
      "Из файла извлекаются только <code>shared_secret</code> и, по вашему выбору, имя аккаунта. <code>identity_secret</code>, session, revocation code и другие поля игнорируются.",
    "import.submit": "Зашифровать и сохранить",
    "import.noFileError": "Выберите один или несколько maFile.",
    "import.tooManyFiles": "За один раз можно загрузить не больше {max} maFile.",
    "import.fileTooLarge": "Размер каждого maFile не должен превышать 1 МБ.",
    "import.aliasEqualsPrimary": "Пользовательский код случайно совпал с основным ID. Измените пользовательский код.",
    "import.aliasMultipleError": "Пользовательский код можно указать только при загрузке одного maFile.",
    "import.success": "Готово. Исходные maFile не отправлялись на сервер; в KV сохранены только зашифрованные контейнеры.",
    "import.partialSuccess": "Импортировано {success} из {total} maFile. Проверьте строки с ошибками.",
    "import.error": "Не удалось импортировать maFile.",
    "alias.hint.empty": "Необязательно. {min}–{max} символов; рекомендуется уникальная длинная фраза.",
    "alias.hint.valid": "Формат подходит. Код не будет отправлен на сервер в открытом виде.",
    "alias.hint.multi": "Пользовательский код доступен только при загрузке одного maFile.",
    "validation.aliasLength": "Пользовательский код должен содержать от {min} до {max} символов.",
    "validation.aliasCharacters": "Разрешены латинские буквы, цифры и символы . _ ~ ! @ # $ % ^ & * + = ? -",
    "validation.accessCodeFormat": "Введите основной ID из {primary} символов или пользовательский код длиной от {min} символов.",
    "mafile.invalidJson": "Файл не является корректным JSON maFile.",
    "mafile.invalidObject": "maFile должен содержать JSON-объект.",
    "mafile.encryptedUnsupported":
      "Зашифрованный maFile SDA не поддерживается. Расшифруйте его локально; пароль Steam вводить на сайт не нужно.",
    "mafile.missingSharedSecret": "В maFile не найден корректный shared_secret.",
    "result.title": "Результат импорта",
    "result.help": "Сохраните основные ID в надёжном месте.",
    "result.primaryLabel": "Основной ID · 16 символов",
    "result.aliasLabel": "Пользовательский код",
    "result.warning":
      "Любой, кто узнает один из этих кодов, сможет получить Steam Guard-код. Не пересылайте их в чатах и не храните в публичном репозитории.",
    "auth.kicker": "Текущий authenticator",
    "auth.codeLabel": "Код для входа в Steam",
    "auth.copyCode": "Скопировать код",
    "auth.countdownAria": "Время до следующего кода",
    "auth.countdownLabel": "Обновление через",
    "auth.note":
      "Код рассчитывается локально по времени вашего устройства. При неверном коде проверьте автоматическую синхронизацию часов.",
    "auth.logout": "Закрыть локальную сессию",
    "auth.seconds": "{count} сек",
    "auth.logoutSuccess": "Локальная сессия очищена.",
    "vault.invalidFormat": "Расшифрованное хранилище имеет неизвестный формат.",
    "vault.invalidSharedSecret": "Расшифрованный shared_secret повреждён.",
    "manage.kicker": "Управление",
    "manage.title": "Альтернативный код",
    "manage.description": "Привяжите или замените пользовательский код. Основной 16-символьный ID останется рабочим.",
    "manage.newAliasLabel": "Новый пользовательский код",
    "manage.newAliasPlaceholder": "my_unique_secret_2026!",
    "manage.bindAlias": "Привязать код",
    "manage.removeAlias": "Отвязать пользовательский код",
    "manage.deleteVault": "Удалить хранилище из KV",
    "manage.aliasOnlyKicker": "Ограниченный доступ",
    "manage.aliasOnlyTitle": "Вход по пользовательскому коду",
    "manage.aliasOnlyDescription":
      "Steam Guard-коды доступны, но для изменения alias или удаления хранилища требуется основной ID.",
    "manage.requirePrimary": "Для изменения кода войдите по основному ID.",
    "manage.bindSuccess":
      "Пользовательский код привязан. В других регионах Cloudflare обновление KV может появиться не мгновенно.",
    "manage.bindError": "Не удалось привязать код.",
    "manage.removeConfirm": "Отвязать пользовательский код? Основной ID продолжит работать.",
    "manage.removeSuccess": "Пользовательский код отвязан.",
    "manage.removeError": "Не удалось отвязать код.",
    "manage.deleteConfirm":
      "Удалить зашифрованное хранилище из Cloudflare KV? Отменить это действие нельзя. Сохранённый локально maFile не изменится.",
    "manage.deleteSuccess": "Хранилище удалено из KV.",
    "manage.deleteError": "Не удалось удалить хранилище.",
    "benefits.eyebrow": "<span></span> Почему SGO (SteamGuardOnline)",
    "benefits.title": "Прозрачная защита.<br />Контроль на вашей стороне.",
    "benefits.openTitle": "Полностью open-source",
    "benefits.openText": "Клиентская криптография, Pages Function и схема хранения доступны для проверки и собственного deploy.",
    "benefits.openLink": "Открыть исходный код",
    "benefits.noLoginTitle": "Без логина и пароля Steam",
    "benefits.noLoginText":
      "Сайт никогда не запрашивает credentials аккаунта. Для генерации кода нужен только локально извлечённый <code>shared_secret</code>.",
    "benefits.encryptTitle": "Шифрование до отправки",
    "benefits.encryptText": "Cloudflare KV получает только AES-GCM ciphertext и обёрнутый ключ. Расшифровка происходит на вашем устройстве.",
    "benefits.devicesTitle": "Доступ с разных устройств",
    "benefits.devicesText": "Основной ID состоит ровно из 16 символов. Дополнительно можно привязать собственный код от 3 символов.",
    "benefits.pinTitle": "PIN для сохранённых профилей",
    "benefits.pinText": "PIN можно включить для сохранённых профилей. При 5 неверных попытках связанное хранилище удаляется из KV.",
    "flow.eyebrow": "<span></span> Как это работает",
    "flow.title": "Ваш maFile остаётся<br />под криптографической защитой",
    "flow.trigger": "Как это работает?",
    "flow.text":
      "Сайт не превращает KV в склад maFiles. Он сохраняет минимальный зашифрованный контейнер, который можно открыть только с помощью основного ID или привязанного пользовательского кода.",
    "flow.step1Title": "Фильтрация",
    "flow.step1Text": "Браузер читает JSON и оставляет только shared_secret и опциональное имя.",
    "flow.step2Title": "Шифрование",
    "flow.step2Text": "Данные шифруются случайным AES-256-GCM ключом до любого сетевого запроса.",
    "flow.step3Title": "Хранение",
    "flow.step3Text": "KV хранит ciphertext и отдельные зашифрованные обёртки ключа для ID и alias.",
    "flow.step4Title": "Генерация",
    "flow.step4Text": "После локальной расшифровки браузер рассчитывает пятисимвольный Steam Guard-код.",
    "faq.eyebrow": "<span></span> Важно знать",
    "faq.title": "Безопасность и ограничения",
    "security.panelAria": "Безопасность и ограничения",
    "faq.encryptedQuestion": "Можно ли загрузить зашифрованный maFile?",
    "faq.encryptedAnswer":
      "Эта версия принимает обычный JSON maFile с полем <code>shared_secret</code>. Она не запрашивает пароль шифрования SDA и тем более пароль Steam. Зашифрованный maFile нужно предварительно открыть локально.",
    "faq.storageQuestion": "Хранится ли полный maFile в Cloudflare KV?",
    "faq.storageAnswer":
      "Нет. Поля для trade confirmations, session tokens, revocation code и device data отбрасываются. Оставшиеся минимальные данные зашифрованы AES-GCM ещё до отправки.",
    "faq.aliasQuestion": "Почему лучше делать пользовательский код длинным?",
    "faq.aliasAnswer":
      "Он является bearer-секретом и ключом к расшифровке. Интерфейс разрешает коды от 3 символов, но короткий или популярный код можно подобрать.",
    "faq.cookieQuestion": "Где хранятся сохранённые профили?",
    "faq.cookieAnswer":
      "PIN для сохранённых профилей включён по умолчанию, но его можно отключить. С PIN cookie хранит ссылку на профиль и соль, а основной ID или пользовательский код хранится в KV в PIN-зашифрованном виде. Без PIN cookie хранит device secret. 5 неверных PIN-попыток удалят хранилище из KV.",
    "faq.steamQuestion": "Это заменяет официальное приложение Steam?",
    "faq.steamAnswer":
      "Технически сайт генерирует коды из существующего shared_secret, но хранение второго фактора онлайн уменьшает разделение факторов. Для максимальной безопасности используйте официальное мобильное приложение Steam.",
    "footer.disclaimer": "Независимый open-source проект. Не связан с Valve Corporation или Steam.",
    "footer.source": "Исходный код",
    "unit.kb": "КБ",
    "file.selected": "{name} · {size} {unit}",
    "file.selectedMultiple": "{count} файлов · {size} {unit}",
    "api.panelAria": "API сайта",
    "api.kicker": "Cloudflare Pages Function",
    "api.title": "API сайта",
    "api.description": "Все изменяющие запросы выполняются как same-origin POST с JSON. API-вызовы отправляются без cookies; saved profiles открываются через profile id и verifier.",
    "api.endpointsAria": "API endpoints",
    "api.endpoint.health": "Проверка готовности API и KV.",
    "api.endpoint.import": "Создаёт зашифрованное хранилище и индексы доступа.",
    "api.endpoint.lookup": "Возвращает encrypted payload и обёрнутый ключ по lookup token.",
    "api.endpoint.alias": "Привязывает, заменяет или удаляет пользовательский код.",
    "api.endpoint.delete": "Удаляет хранилище и связанные индексы из KV.",
    "api.endpoint.saveSaved": "Сохраняет PIN-зашифрованный access ID для профиля.",
    "api.endpoint.openSaved": "Проверяет verifier и возвращает encrypted access ID.",
    "api.endpoint.deleteSaved": "Удаляет saved profile и связанное хранилище.",
    "api.note": "Ответы API отдаются с Cache-Control: no-store. Browser requests с чужим Origin отклоняются.",
    "api.invalidResponse": "Сервер вернул некорректный ответ.",
    "api.requestFailed": "Запрос завершился ошибкой.",
    "api.lookup.404": "Хранилище не найдено. Проверьте секретный код.",
    "api.import.409": "Такой ID или пользовательский код уже занят.",
    "api.alias.403": "Для управления требуется основной ID.",
    "api.alias.409": "Пользовательский код уже занят.",
    "api.delete.403": "Для удаления требуется основной ID.",
    "api.400": "Запрос имеет некорректный формат.",
    "api.413": "Запрос слишком большой.",
    "api.415": "Ожидается Content-Type: application/json.",
    "api.429": "Слишком много запросов. Повторите попытку позже.",
    "api.503": "Сервис временно недоступен или KV ещё настраивается.",
  },
  en: {
    "meta.title": "SGO (SteamGuardOnline) — Online Steam Desktop Authenticator",
    "meta.description":
      "Open-source online Steam Desktop Authenticator for safely getting Steam Guard codes by secret ID without a Steam login or password.",
    "language.label": "Language",
    "language.aria": "Site language",
    "brand.homeAria": "SGO (SteamGuardOnline) — home",
    "header.projectLinksAria": "Project links",
    "header.infoTabsAria": "Information sections",
    "service.checking": "Checking API…",
    "service.ready": "API and KV ready",
    "service.warning": "KV setup required",
    "hero.eyebrow": "<span></span> Online Steam Desktop Authenticator",
    "hero.title": "Steam Guard codes<br /><em>on any device</em>",
    "hero.lead":
      "Upload a maFile once, save the 16-character ID, and open the current Steam Guard code from another computer or phone. No Steam login or password is needed.",
    "hero.pointsAria": "Main features",
    "hero.point.encrypt": "maFile is encrypted in the browser",
    "hero.point.noUrl": "The id parameter is cleared from the URL after reading",
    "hero.point.noScripts": "No third-party scripts",
    "vault.kicker": "Encrypted vault",
    "vault.title": "Open or create SGO",
    "vault.modeAria": "Work mode",
    "vault.tab.access": "Get code",
    "vault.tab.import": "Upload maFile",
    "vault.tab.security": "Security",
    "vault.tab.api": "API",
    "access.panelAria": "Open vault",
    "access.label": "Primary ID or custom code",
    "access.placeholder": "Example: super_secret_code123",
    "access.help": "The code is converted into a cryptographic token locally. If a saved profile is PIN-protected, the site asks for the PIN before opening it.",
    "access.submit": "Open authenticator",
    "access.openSuccess": "Vault decrypted locally in the browser.",
    "access.openError": "Could not open the vault.",
    "profiles.title": "Saved profiles",
    "profiles.empty": "No saved profiles yet.",
    "profiles.open": "Open",
    "profiles.remove": "Remove",
    "profiles.clear": "Clear",
    "profiles.clearConfirm": "Delete all saved profiles from this browser storage?",
    "profiles.rememberTitle": "Remember profile on this device",
    "profiles.rememberHelp": "The profile is saved in this browser storage without expiration. PIN-protected profiles ask for the PIN when opened.",
    "profiles.pinEnabledTitle": "Protect the saved profile with a PIN",
    "profiles.pinEnabledHelp": "If PIN is off, browser storage access can open the profile without an extra secret.",
    "profiles.pinLabel": "Profile PIN",
    "profiles.pinPlaceholder": "3-6",
    "profiles.pinHelp": "The PIN is optional, but it protects the saved profile from direct use of browser storage data. 5 wrong attempts delete the vault from KV.",
    "profiles.pinUnlockTitle": "Enter PIN for {label}",
    "profiles.pinUnlockHelp": "5 wrong attempts delete the linked vault from KV.",
    "profiles.pinDisabledWarning": "PIN protection is off. Security is lower: if browser storage is accessed, the profile can be opened without a PIN.",
    "profiles.pinInvalid": "Enter a PIN from 3 to 6 printable characters.",
    "profiles.rememberImportedTitle": "Add created IDs to profiles",
    "profiles.rememberImportedHelp": "After import they will appear on the get-code tab.",
    "profiles.cookieHelp": "With PIN, the browser stores a profile reference and salt while the access ID stays PIN-encrypted in KV. Without PIN, the browser stores a device secret. 5 wrong PIN attempts delete the vault from KV.",
    "profiles.kind.primary": "Primary ID",
    "profiles.kind.alias": "Custom code",
    "profiles.pinProtected": "PIN",
    "profiles.noPin": "no PIN",
    "profiles.noPinShort": "no PIN",
    "profiles.deviceSecretMissing": "This no-PIN profile is damaged or was created in another browser.",
    "profiles.saved": "Profile saved on this device.",
    "profiles.savedCount": "Saved profiles: {count}.",
    "profiles.removed": "Profile removed.",
    "profiles.cleared": "Saved profiles cleared.",
    "profiles.saveError": "Could not save the profile.",
    "profiles.attemptsLeft": "{count} left",
    "profiles.pinWrong": "Wrong PIN.",
    "profiles.pinWrongWithAttempts": "Wrong PIN. Attempts left: {count}. After 5 wrong attempts the vault will be deleted from KV.",
    "profiles.deletedAfterAttempts": "The PIN was entered incorrectly 5 times. The vault was deleted from KV and the profile was removed from the browser.",
    "profiles.deleteAfterAttemptsError": "Could not delete the vault after 5 wrong PIN attempts.",
    "accessKind.primary": "Primary ID",
    "accessKind.alias": "Custom code",
    "action.show": "Show",
    "action.hide": "Hide",
    "action.copy": "Copy",
    "action.cancel": "Cancel",
    "busy.processing": "Processing…",
    "busy.decrypting": "Decrypting…",
    "busy.encrypting": "Encrypting…",
    "busy.binding": "Binding…",
    "toast.copied": "Copied",
    "copy.primary": "Primary ID copied",
    "copy.alias": "Custom code copied",
    "copy.guard": "Steam Guard code copied",
    "import.panelAria": "Import maFile",
    "import.noFile": "No files selected",
    "import.dropTitle": "Drop maFile here",
    "import.dropSubtitle": "or click to choose one or more files",
    "import.aliasLabelHtml": "Your access code <span>optional</span>",
    "import.aliasPlaceholder": "super_secret_code123",
    "import.keepLabelTitle": "Save account name",
    "import.keepLabelHelp": "The name is stored only inside the encrypted container.",
    "import.security":
      "Only <code>shared_secret</code> and, if you choose, the account name are extracted. <code>identity_secret</code>, session, revocation code, and other fields are ignored.",
    "import.submit": "Encrypt and save",
    "import.noFileError": "Choose one or more maFiles.",
    "import.tooManyFiles": "You can upload up to {max} maFiles at once.",
    "import.fileTooLarge": "Each maFile must not exceed 1 MB.",
    "import.aliasEqualsPrimary": "The custom code randomly matched the primary ID. Change the custom code.",
    "import.aliasMultipleError": "A custom code can be used only when uploading one maFile.",
    "import.success": "Done. Source maFiles were not sent to the server; only encrypted containers were saved to KV.",
    "import.partialSuccess": "{success} of {total} maFiles imported. Check the failed rows.",
    "import.error": "Could not import the maFile.",
    "alias.hint.empty": "Optional. {min}-{max} characters; a unique long phrase is recommended.",
    "alias.hint.valid": "Format looks good. The code will not be sent to the server in plaintext.",
    "alias.hint.multi": "A custom code is available only when uploading one maFile.",
    "validation.aliasLength": "Custom code must contain {min} to {max} characters.",
    "validation.aliasCharacters": "Use Latin letters, digits, and these symbols: . _ ~ ! @ # $ % ^ & * + = ? -",
    "validation.accessCodeFormat": "Enter a {primary}-character primary ID or a custom code at least {min} characters long.",
    "mafile.invalidJson": "The file is not valid JSON maFile.",
    "mafile.invalidObject": "maFile must contain a JSON object.",
    "mafile.encryptedUnsupported":
      "Encrypted SDA maFiles are not supported. Decrypt it locally; you do not need to enter your Steam password here.",
    "mafile.missingSharedSecret": "No valid shared_secret was found in the maFile.",
    "result.title": "Import result",
    "result.help": "Save the primary IDs in a safe place.",
    "result.primaryLabel": "Primary ID · 16 characters",
    "result.aliasLabel": "Custom code",
    "result.warning":
      "Anyone who learns one of these codes can get the Steam Guard code. Do not send them in chats or store them in a public repository.",
    "auth.kicker": "Current authenticator",
    "auth.codeLabel": "Code for Steam sign-in",
    "auth.copyCode": "Copy code",
    "auth.countdownAria": "Time until next code",
    "auth.countdownLabel": "Updates in",
    "auth.note": "The code is calculated locally using your device time. If the code is wrong, check automatic clock sync.",
    "auth.logout": "Close local session",
    "auth.seconds": "{count} sec",
    "auth.logoutSuccess": "Local session cleared.",
    "vault.invalidFormat": "The decrypted vault has an unknown format.",
    "vault.invalidSharedSecret": "The decrypted shared_secret is damaged.",
    "manage.kicker": "Management",
    "manage.title": "Alternative code",
    "manage.description": "Bind or replace the custom code. The primary 16-character ID will keep working.",
    "manage.newAliasLabel": "New custom code",
    "manage.newAliasPlaceholder": "my_unique_secret_2026!",
    "manage.bindAlias": "Bind code",
    "manage.removeAlias": "Unbind custom code",
    "manage.deleteVault": "Delete vault from KV",
    "manage.aliasOnlyKicker": "Limited access",
    "manage.aliasOnlyTitle": "Signed in with custom code",
    "manage.aliasOnlyDescription": "Steam Guard codes are available, but changing alias or deleting the vault requires the primary ID.",
    "manage.requirePrimary": "Sign in with the primary ID to change the code.",
    "manage.bindSuccess": "Custom code bound. In other Cloudflare regions, the KV update may not appear immediately.",
    "manage.bindError": "Could not bind the code.",
    "manage.removeConfirm": "Unbind the custom code? The primary ID will keep working.",
    "manage.removeSuccess": "Custom code unbound.",
    "manage.removeError": "Could not unbind the code.",
    "manage.deleteConfirm":
      "Delete the encrypted vault from Cloudflare KV? This cannot be undone. Your locally saved maFile will not change.",
    "manage.deleteSuccess": "Vault deleted from KV.",
    "manage.deleteError": "Could not delete the vault.",
    "benefits.eyebrow": "<span></span> Why SGO (SteamGuardOnline)",
    "benefits.title": "Transparent protection.<br />Control stays with you.",
    "benefits.openTitle": "Fully open-source",
    "benefits.openText": "Client-side cryptography, Pages Function, and the storage model are available for review and self-deploy.",
    "benefits.openLink": "Open source code",
    "benefits.noLoginTitle": "No Steam login or password",
    "benefits.noLoginText":
      "The site never asks for account credentials. Code generation only needs the locally extracted <code>shared_secret</code>.",
    "benefits.encryptTitle": "Encrypted before upload",
    "benefits.encryptText": "Cloudflare KV receives only AES-GCM ciphertext and a wrapped key. Decryption happens on your device.",
    "benefits.devicesTitle": "Access from different devices",
    "benefits.devicesText": "The primary ID is exactly 16 characters. You can also bind your own code from 3 characters.",
    "benefits.pinTitle": "PIN for saved profiles",
    "benefits.pinText": "PIN protection can be enabled for saved profiles. After 5 wrong attempts, the linked vault is deleted from KV.",
    "flow.eyebrow": "<span></span> How it works",
    "flow.title": "Your maFile stays<br />under cryptographic protection",
    "flow.trigger": "How does it work?",
    "flow.text":
      "The site does not turn KV into a maFile dump. It saves a minimal encrypted container that can be opened only with the primary ID or a bound custom code.",
    "flow.step1Title": "Filtering",
    "flow.step1Text": "The browser reads JSON and keeps only shared_secret and an optional name.",
    "flow.step2Title": "Encryption",
    "flow.step2Text": "Data is encrypted with a random AES-256-GCM key before any network request.",
    "flow.step3Title": "Storage",
    "flow.step3Text": "KV stores ciphertext and separate encrypted key wraps for the ID and alias.",
    "flow.step4Title": "Generation",
    "flow.step4Text": "After local decryption, the browser calculates the five-character Steam Guard code.",
    "faq.eyebrow": "<span></span> Important",
    "faq.title": "Security and limits",
    "security.panelAria": "Security and limitations",
    "faq.encryptedQuestion": "Can I upload an encrypted maFile?",
    "faq.encryptedAnswer":
      "This version accepts a normal JSON maFile with a <code>shared_secret</code> field. It does not ask for an SDA encryption password, and never asks for your Steam password. Open an encrypted maFile locally first.",
    "faq.storageQuestion": "Is the full maFile stored in Cloudflare KV?",
    "faq.storageAnswer":
      "No. Fields for trade confirmations, session tokens, revocation code, and device data are discarded. The remaining minimal data is encrypted with AES-GCM before upload.",
    "faq.aliasQuestion": "Why is a longer custom code better?",
    "faq.aliasAnswer":
      "It is a bearer secret and a decryption key. The interface allows codes from 3 characters, but a short or common code can be guessed.",
    "faq.cookieQuestion": "Where are saved profiles stored?",
    "faq.cookieAnswer":
      "PIN for saved profiles is enabled by default, but can be turned off. With PIN, the cookie stores a profile reference and salt while the primary ID or custom code is stored in KV encrypted with the PIN. Without PIN, the cookie stores a device secret. 5 wrong PIN attempts delete the vault from KV.",
    "faq.steamQuestion": "Does this replace the official Steam app?",
    "faq.steamAnswer":
      "Technically, the site generates codes from an existing shared_secret, but storing a second factor online weakens factor separation. For maximum security, use the official Steam mobile app.",
    "footer.disclaimer": "Independent open-source project. Not affiliated with Valve Corporation or Steam.",
    "footer.source": "Source code",
    "unit.kb": "KB",
    "file.selected": "{name} · {size} {unit}",
    "file.selectedMultiple": "{count} files · {size} {unit}",
    "api.panelAria": "Site API",
    "api.kicker": "Cloudflare Pages Function",
    "api.title": "Site API",
    "api.description": "All mutating requests are same-origin JSON POST requests. API calls are sent without cookies; saved profiles open through a profile id and verifier.",
    "api.endpointsAria": "API endpoints",
    "api.endpoint.health": "Checks API and KV readiness.",
    "api.endpoint.import": "Creates an encrypted vault and access indexes.",
    "api.endpoint.lookup": "Returns the encrypted payload and wrapped key for a lookup token.",
    "api.endpoint.alias": "Binds, replaces, or removes a custom code.",
    "api.endpoint.delete": "Deletes the vault and linked indexes from KV.",
    "api.endpoint.saveSaved": "Saves a PIN-encrypted access ID for a profile.",
    "api.endpoint.openSaved": "Checks the verifier and returns the encrypted access ID.",
    "api.endpoint.deleteSaved": "Deletes the saved profile and linked vault.",
    "api.note": "API responses use Cache-Control: no-store. Browser requests with a foreign Origin are rejected.",
    "api.invalidResponse": "The server returned an invalid response.",
    "api.requestFailed": "The request failed.",
    "api.lookup.404": "Vault not found. Check the secret code.",
    "api.import.409": "That ID or custom code is already taken.",
    "api.alias.403": "Management requires the primary ID.",
    "api.alias.409": "The custom code is already taken.",
    "api.delete.403": "Deletion requires the primary ID.",
    "api.400": "The request has an invalid format.",
    "api.413": "The request is too large.",
    "api.415": "Expected Content-Type: application/json.",
    "api.429": "Too many requests. Try again later.",
    "api.503": "The service is temporarily unavailable or KV is still being configured.",
  },
  "zh-CN": {
    "meta.title": "SGO (SteamGuardOnline) — 在线 Steam Desktop Authenticator",
    "meta.description": "开源在线 Steam Desktop Authenticator，可通过秘密 ID 安全获取 Steam Guard 代码，无需 Steam 登录名或密码。",
    "language.label": "语言",
    "language.aria": "网站语言",
    "brand.homeAria": "SGO (SteamGuardOnline) — 首页",
    "header.projectLinksAria": "项目链接",
    "header.infoTabsAria": "信息部分",
    "service.checking": "正在检查 API…",
    "service.ready": "API 和 KV 已就绪",
    "service.warning": "需要配置 KV",
    "hero.eyebrow": "<span></span> 在线 Steam Desktop Authenticator",
    "hero.title": "Steam Guard 代码<br /><em>可在任何设备使用</em>",
    "hero.lead": "上传一次 maFile，保存 16 位 ID，就可以在另一台电脑或手机上打开当前 Steam Guard 代码。不需要 Steam 登录名或密码。",
    "hero.pointsAria": "主要特性",
    "hero.point.encrypt": "maFile 在浏览器中加密",
    "hero.point.noUrl": "读取后会从 URL 清除 id 参数",
    "hero.point.noScripts": "无第三方脚本",
    "vault.kicker": "加密保险库",
    "vault.title": "打开或创建 SGO",
    "vault.modeAria": "工作模式",
    "vault.tab.access": "获取代码",
    "vault.tab.import": "上传 maFile",
    "vault.tab.security": "安全",
    "vault.tab.api": "API",
    "access.panelAria": "打开保险库",
    "access.label": "主 ID 或自定义代码",
    "access.placeholder": "例如：super_secret_code123",
    "access.help": "代码会在本地转换为加密 token。如果保存的配置受 PIN 保护，网站会在打开前要求输入 PIN。",
    "access.submit": "打开 authenticator",
    "access.openSuccess": "保险库已在浏览器本地解密。",
    "access.openError": "无法打开保险库。",
    "profiles.title": "已保存的配置",
    "profiles.empty": "还没有保存的配置。",
    "profiles.open": "打开",
    "profiles.remove": "删除",
    "profiles.clear": "清空",
    "profiles.clearConfirm": "从此浏览器存储中删除所有已保存配置？",
    "profiles.rememberTitle": "在此设备记住配置",
    "profiles.rememberHelp": "配置会保存在此浏览器存储中且不设置过期时间。受 PIN 保护的配置在打开时会要求输入 PIN。",
    "profiles.pinEnabledTitle": "用 PIN 保护保存的配置",
    "profiles.pinEnabledHelp": "如果关闭 PIN，能访问浏览器存储的人可在没有额外 secret 的情况下打开配置。",
    "profiles.pinLabel": "配置 PIN",
    "profiles.pinPlaceholder": "3–6",
    "profiles.pinHelp": "PIN 是可选的，但可防止浏览器存储数据被直接使用。5 次错误尝试会从 KV 删除保险库。",
    "profiles.pinUnlockTitle": "输入 {label} 的 PIN",
    "profiles.pinUnlockHelp": "5 次错误尝试会从 KV 删除关联保险库。",
    "profiles.pinDisabledWarning": "PIN 保护已关闭。安全级别降低：浏览器存储被访问后，配置可在没有 PIN 的情况下打开。",
    "profiles.pinInvalid": "请输入 3 到 6 个可打印字符的 PIN。",
    "profiles.rememberImportedTitle": "将创建的 ID 添加到配置",
    "profiles.rememberImportedHelp": "导入后它们会显示在获取代码标签页。",
    "profiles.cookieHelp": "启用 PIN 时，浏览器保存配置引用和盐，access ID 以 PIN 加密形式保存在 KV。关闭 PIN 时，浏览器保存 device secret。5 次错误 PIN 尝试会从 KV 删除保险库。",
    "profiles.kind.primary": "主 ID",
    "profiles.kind.alias": "自定义代码",
    "profiles.pinProtected": "PIN",
    "profiles.noPin": "无 PIN",
    "profiles.noPinShort": "无 PIN",
    "profiles.deviceSecretMissing": "此无 PIN 配置已损坏，或是在另一个浏览器中创建的。",
    "profiles.saved": "配置已保存在此设备上。",
    "profiles.savedCount": "已保存配置：{count}。",
    "profiles.removed": "配置已删除。",
    "profiles.cleared": "已保存的配置已清空。",
    "profiles.saveError": "无法保存配置。",
    "profiles.attemptsLeft": "剩余 {count}",
    "profiles.pinWrong": "PIN 错误。",
    "profiles.pinWrongWithAttempts": "PIN 错误。剩余尝试次数：{count}。5 次错误后保险库将从 KV 删除。",
    "profiles.deletedAfterAttempts": "PIN 已连续 5 次输入错误。保险库已从 KV 删除，配置已从浏览器删除。",
    "profiles.deleteAfterAttemptsError": "5 次错误 PIN 后无法删除保险库。",
    "accessKind.primary": "主 ID",
    "accessKind.alias": "自定义代码",
    "action.show": "显示",
    "action.hide": "隐藏",
    "action.copy": "复制",
    "action.cancel": "取消",
    "busy.processing": "处理中…",
    "busy.decrypting": "解密中…",
    "busy.encrypting": "加密中…",
    "busy.binding": "绑定中…",
    "toast.copied": "已复制",
    "copy.primary": "主 ID 已复制",
    "copy.alias": "自定义代码已复制",
    "copy.guard": "Steam Guard 代码已复制",
    "import.panelAria": "导入 maFile",
    "import.noFile": "未选择文件",
    "import.dropTitle": "将 maFile 拖到这里",
    "import.dropSubtitle": "或点击选择一个或多个文件",
    "import.aliasLabelHtml": "你的访问代码 <span>可选</span>",
    "import.aliasPlaceholder": "super_secret_code123",
    "import.keepLabelTitle": "保存账号名称",
    "import.keepLabelHelp": "名称只会保存在加密容器内。",
    "import.security":
      "只会提取 <code>shared_secret</code>，以及你选择保留的账号名称。<code>identity_secret</code>、session、revocation code 和其他字段会被忽略。",
    "import.submit": "加密并保存",
    "import.noFileError": "请选择一个或多个 maFile。",
    "import.tooManyFiles": "一次最多可上传 {max} 个 maFile。",
    "import.fileTooLarge": "每个 maFile 大小不能超过 1 MB。",
    "import.aliasEqualsPrimary": "自定义代码意外与主 ID 相同。请更改自定义代码。",
    "import.aliasMultipleError": "自定义代码只能用于上传一个 maFile。",
    "import.success": "完成。原始 maFile 未发送到服务器；KV 中只保存了加密容器。",
    "import.partialSuccess": "已导入 {success}/{total} 个 maFile。请检查失败的行。",
    "import.error": "无法导入 maFile。",
    "alias.hint.empty": "可选。{min}-{max} 个字符；建议使用唯一的长短语。",
    "alias.hint.valid": "格式可用。代码不会以明文发送到服务器。",
    "alias.hint.multi": "自定义代码只能在上传一个 maFile 时使用。",
    "validation.aliasLength": "自定义代码必须包含 {min} 到 {max} 个字符。",
    "validation.aliasCharacters": "可使用拉丁字母、数字和这些符号：. _ ~ ! @ # $ % ^ & * + = ? -",
    "validation.accessCodeFormat": "请输入 {primary} 位主 ID，或至少 {min} 个字符的自定义代码。",
    "mafile.invalidJson": "该文件不是有效的 JSON maFile。",
    "mafile.invalidObject": "maFile 必须包含 JSON 对象。",
    "mafile.encryptedUnsupported": "不支持加密的 SDA maFile。请先在本地解密；这里不需要输入 Steam 密码。",
    "mafile.missingSharedSecret": "maFile 中没有找到有效的 shared_secret。",
    "result.title": "导入结果",
    "result.help": "请将主 ID 保存在安全位置。",
    "result.primaryLabel": "主 ID · 16 个字符",
    "result.aliasLabel": "自定义代码",
    "result.warning": "任何知道这些代码之一的人都可以获取 Steam Guard 代码。不要在聊天中发送，也不要存放在公开仓库中。",
    "auth.kicker": "当前 authenticator",
    "auth.codeLabel": "Steam 登录代码",
    "auth.copyCode": "复制代码",
    "auth.countdownAria": "距离下一代码的时间",
    "auth.countdownLabel": "更新倒计时",
    "auth.note": "代码会根据设备时间在本地计算。如果代码错误，请检查自动时间同步。",
    "auth.logout": "关闭本地会话",
    "auth.seconds": "{count} 秒",
    "auth.logoutSuccess": "本地会话已清除。",
    "vault.invalidFormat": "解密后的保险库格式未知。",
    "vault.invalidSharedSecret": "解密后的 shared_secret 已损坏。",
    "manage.kicker": "管理",
    "manage.title": "备用代码",
    "manage.description": "绑定或替换自定义代码。16 位主 ID 会继续可用。",
    "manage.newAliasLabel": "新的自定义代码",
    "manage.newAliasPlaceholder": "my_unique_secret_2026!",
    "manage.bindAlias": "绑定代码",
    "manage.removeAlias": "解绑自定义代码",
    "manage.deleteVault": "从 KV 删除保险库",
    "manage.aliasOnlyKicker": "受限访问",
    "manage.aliasOnlyTitle": "使用自定义代码登录",
    "manage.aliasOnlyDescription": "可以查看 Steam Guard 代码，但修改 alias 或删除保险库需要主 ID。",
    "manage.requirePrimary": "请使用主 ID 登录后再更改代码。",
    "manage.bindSuccess": "自定义代码已绑定。在其他 Cloudflare 区域，KV 更新可能不会立即可见。",
    "manage.bindError": "无法绑定代码。",
    "manage.removeConfirm": "解绑自定义代码？主 ID 会继续可用。",
    "manage.removeSuccess": "自定义代码已解绑。",
    "manage.removeError": "无法解绑代码。",
    "manage.deleteConfirm": "从 Cloudflare KV 删除加密保险库？此操作无法撤销。本地保存的 maFile 不会改变。",
    "manage.deleteSuccess": "保险库已从 KV 删除。",
    "manage.deleteError": "无法删除保险库。",
    "benefits.eyebrow": "<span></span> 为什么选择 SGO (SteamGuardOnline)",
    "benefits.title": "透明保护。<br />控制权由你掌握。",
    "benefits.openTitle": "完全开源",
    "benefits.openText": "客户端加密、Pages Function 和存储模型都可审查，也可自行部署。",
    "benefits.openLink": "打开源代码",
    "benefits.noLoginTitle": "无需 Steam 登录名和密码",
    "benefits.noLoginText": "网站从不要求账号 credentials。生成代码只需要本地提取的 <code>shared_secret</code>。",
    "benefits.encryptTitle": "上传前加密",
    "benefits.encryptText": "Cloudflare KV 只接收 AES-GCM ciphertext 和包裹后的密钥。解密在你的设备上完成。",
    "benefits.devicesTitle": "可从不同设备访问",
    "benefits.devicesText": "主 ID 固定为 16 个字符。也可以绑定 3 个字符起的自定义代码。",
    "benefits.pinTitle": "保存配置的 PIN",
    "benefits.pinText": "保存的配置可以启用 PIN 保护。5 次错误尝试后，关联保险库会从 KV 删除。",
    "flow.eyebrow": "<span></span> 工作方式",
    "flow.title": "你的 maFile 始终<br />受加密保护",
    "flow.trigger": "工作方式？",
    "flow.text": "网站不会把 KV 变成 maFile 仓库。它只保存一个最小加密容器，只能用主 ID 或绑定的自定义代码打开。",
    "flow.step1Title": "过滤",
    "flow.step1Text": "浏览器读取 JSON，只保留 shared_secret 和可选名称。",
    "flow.step2Title": "加密",
    "flow.step2Text": "数据在任何网络请求前，使用随机 AES-256-GCM 密钥加密。",
    "flow.step3Title": "存储",
    "flow.step3Text": "KV 保存 ciphertext，并为 ID 和 alias 保存单独的加密密钥包裹。",
    "flow.step4Title": "生成",
    "flow.step4Text": "本地解密后，浏览器计算 5 位 Steam Guard 代码。",
    "faq.eyebrow": "<span></span> 重要信息",
    "faq.title": "安全和限制",
    "security.panelAria": "安全和限制",
    "faq.encryptedQuestion": "可以上传加密的 maFile 吗？",
    "faq.encryptedAnswer": "此版本接受带有 <code>shared_secret</code> 字段的普通 JSON maFile。它不会要求 SDA 加密密码，也不会要求 Steam 密码。加密 maFile 需要先在本地打开。",
    "faq.storageQuestion": "完整 maFile 会存储在 Cloudflare KV 吗？",
    "faq.storageAnswer": "不会。trade confirmations、session tokens、revocation code 和 device data 等字段会被丢弃。剩余的最小数据会在上传前用 AES-GCM 加密。",
    "faq.aliasQuestion": "为什么自定义代码最好更长？",
    "faq.aliasAnswer": "它是 bearer secret，也是解密密钥。界面允许 3 个字符起的代码，但短代码或常见代码可能被猜中。",
    "faq.cookieQuestion": "已保存的配置存在哪里？",
    "faq.cookieAnswer": "保存配置的 PIN 默认启用，但可以关闭。启用 PIN 时，cookie 保存资料引用和盐，主 ID 或自定义代码以 PIN 加密形式保存在 KV。关闭 PIN 时，cookie 保存 device secret。5 次错误 PIN 尝试会从 KV 删除保险库。",
    "faq.steamQuestion": "这会替代官方 Steam 应用吗？",
    "faq.steamAnswer": "技术上，网站从已有 shared_secret 生成代码，但将第二因素存放在线上会削弱因素隔离。为获得最高安全性，请使用官方 Steam 手机应用。",
    "footer.disclaimer": "独立开源项目。与 Valve Corporation 或 Steam 无关联。",
    "footer.source": "源代码",
    "unit.kb": "KB",
    "file.selected": "{name} · {size} {unit}",
    "file.selectedMultiple": "{count} 个文件 · {size} {unit}",
    "api.panelAria": "网站 API",
    "api.kicker": "Cloudflare Pages Function",
    "api.title": "网站 API",
    "api.description": "所有会修改数据的请求都是 same-origin JSON POST。API 调用不发送 cookie；保存的配置通过 profile id 和 verifier 打开。",
    "api.endpointsAria": "API endpoints",
    "api.endpoint.health": "检查 API 和 KV 是否就绪。",
    "api.endpoint.import": "创建加密保险库和访问索引。",
    "api.endpoint.lookup": "根据 lookup token 返回 encrypted payload 和 wrapped key。",
    "api.endpoint.alias": "绑定、替换或移除自定义代码。",
    "api.endpoint.delete": "从 KV 删除保险库及关联索引。",
    "api.endpoint.saveSaved": "为配置保存 PIN 加密的 access ID。",
    "api.endpoint.openSaved": "检查 verifier 并返回 encrypted access ID。",
    "api.endpoint.deleteSaved": "删除 saved profile 和关联保险库。",
    "api.note": "API 响应使用 Cache-Control: no-store。带有外部 Origin 的浏览器请求会被拒绝。",
    "api.invalidResponse": "服务器返回了无效响应。",
    "api.requestFailed": "请求失败。",
    "api.lookup.404": "未找到保险库。请检查秘密代码。",
    "api.import.409": "该 ID 或自定义代码已被占用。",
    "api.alias.403": "管理操作需要主 ID。",
    "api.alias.409": "自定义代码已被占用。",
    "api.delete.403": "删除需要主 ID。",
    "api.400": "请求格式无效。",
    "api.413": "请求过大。",
    "api.415": "需要 Content-Type: application/json。",
    "api.429": "请求过多。请稍后再试。",
    "api.503": "服务暂不可用，或 KV 仍在配置中。",
  },
  es: {
    "meta.title": "SGO (SteamGuardOnline) — Steam Desktop Authenticator online",
    "meta.description": "Steam Desktop Authenticator online y open-source para obtener códigos Steam Guard mediante un ID secreto, sin usuario ni contraseña de Steam.",
    "language.label": "Idioma",
    "language.aria": "Idioma del sitio",
    "brand.homeAria": "SGO (SteamGuardOnline) — inicio",
    "header.projectLinksAria": "Enlaces del proyecto",
    "header.infoTabsAria": "Secciones de información",
    "service.checking": "Comprobando API…",
    "service.ready": "API y KV listos",
    "service.warning": "Hay que configurar KV",
    "hero.eyebrow": "<span></span> Steam Desktop Authenticator online",
    "hero.title": "Códigos Steam Guard<br /><em>en cualquier dispositivo</em>",
    "hero.lead": "Sube un maFile una vez, guarda el ID de 16 caracteres y abre el código actual de Steam Guard desde otro ordenador o teléfono. No hace falta usuario ni contraseña de Steam.",
    "hero.pointsAria": "Funciones principales",
    "hero.point.encrypt": "maFile se cifra en el navegador",
    "hero.point.noUrl": "El parámetro id se borra de la URL tras leerlo",
    "hero.point.noScripts": "Sin scripts de terceros",
    "vault.kicker": "Bóveda cifrada",
    "vault.title": "Abrir o crear SGO",
    "vault.modeAria": "Modo de trabajo",
    "vault.tab.access": "Obtener código",
    "vault.tab.import": "Subir maFile",
    "vault.tab.security": "Seguridad",
    "vault.tab.api": "API",
    "access.panelAria": "Abrir bóveda",
    "access.label": "ID principal o código personalizado",
    "access.placeholder": "Ejemplo: super_secret_code123",
    "access.help": "El código se convierte localmente en un token criptográfico. Si un perfil guardado está protegido con PIN, el sitio pedirá el PIN antes de abrirlo.",
    "access.submit": "Abrir authenticator",
    "access.openSuccess": "Bóveda descifrada localmente en el navegador.",
    "access.openError": "No se pudo abrir la bóveda.",
    "profiles.title": "Perfiles guardados",
    "profiles.empty": "Aún no hay perfiles guardados.",
    "profiles.open": "Abrir",
    "profiles.remove": "Eliminar",
    "profiles.clear": "Limpiar",
    "profiles.clearConfirm": "¿Eliminar todos los perfiles guardados del almacenamiento de este navegador?",
    "profiles.rememberTitle": "Recordar perfil en este dispositivo",
    "profiles.rememberHelp": "El perfil se guarda en el almacenamiento de este navegador sin caducidad. Los perfiles protegidos con PIN pedirán el PIN al abrirse.",
    "profiles.pinEnabledTitle": "Proteger el perfil guardado con PIN",
    "profiles.pinEnabledHelp": "Si el PIN está desactivado, el acceso al almacenamiento del navegador puede abrir el perfil sin un secreto adicional.",
    "profiles.pinLabel": "PIN del perfil",
    "profiles.pinPlaceholder": "3-6",
    "profiles.pinHelp": "El PIN es opcional, pero protege el perfil guardado contra el uso directo de los datos del almacenamiento del navegador. 5 intentos erróneos eliminan la bóveda de KV.",
    "profiles.pinUnlockTitle": "Introduce el PIN para {label}",
    "profiles.pinUnlockHelp": "5 intentos erróneos eliminan la bóveda vinculada de KV.",
    "profiles.pinDisabledWarning": "La protección con PIN está desactivada. La seguridad baja: si se accede al almacenamiento del navegador, el perfil podrá abrirse sin PIN.",
    "profiles.pinInvalid": "Introduce un PIN de 3 a 6 caracteres imprimibles.",
    "profiles.rememberImportedTitle": "Añadir los ID creados a perfiles",
    "profiles.rememberImportedHelp": "Después de importar aparecerán en la pestaña para obtener código.",
    "profiles.cookieHelp": "Con PIN, el navegador guarda una referencia del perfil y la sal, mientras el access ID queda cifrado con PIN en KV. Sin PIN, el navegador guarda un device secret. 5 PIN erróneos eliminan la bóveda de KV.",
    "profiles.kind.primary": "ID principal",
    "profiles.kind.alias": "Código personalizado",
    "profiles.pinProtected": "PIN",
    "profiles.noPin": "sin PIN",
    "profiles.noPinShort": "sin PIN",
    "profiles.deviceSecretMissing": "Este perfil sin PIN está dañado o se creó en otro navegador.",
    "profiles.saved": "Perfil guardado en este dispositivo.",
    "profiles.savedCount": "Perfiles guardados: {count}.",
    "profiles.removed": "Perfil eliminado.",
    "profiles.cleared": "Perfiles guardados eliminados.",
    "profiles.saveError": "No se pudo guardar el perfil.",
    "profiles.attemptsLeft": "quedan {count}",
    "profiles.pinWrong": "PIN incorrecto.",
    "profiles.pinWrongWithAttempts": "PIN incorrecto. Intentos restantes: {count}. Tras 5 intentos erróneos, la bóveda se eliminará de KV.",
    "profiles.deletedAfterAttempts": "El PIN se introdujo mal 5 veces. La bóveda se eliminó de KV y el perfil se eliminó del navegador.",
    "profiles.deleteAfterAttemptsError": "No se pudo eliminar la bóveda tras 5 intentos de PIN erróneos.",
    "accessKind.primary": "ID principal",
    "accessKind.alias": "Código personalizado",
    "action.show": "Mostrar",
    "action.hide": "Ocultar",
    "action.copy": "Copiar",
    "action.cancel": "Cancelar",
    "busy.processing": "Procesando…",
    "busy.decrypting": "Descifrando…",
    "busy.encrypting": "Cifrando…",
    "busy.binding": "Vinculando…",
    "toast.copied": "Copiado",
    "copy.primary": "ID principal copiado",
    "copy.alias": "Código personalizado copiado",
    "copy.guard": "Código Steam Guard copiado",
    "import.panelAria": "Importar maFile",
    "import.noFile": "Ningún archivo seleccionado",
    "import.dropTitle": "Suelta el maFile aquí",
    "import.dropSubtitle": "o haz clic para elegir uno o varios archivos",
    "import.aliasLabelHtml": "Tu código de acceso <span>opcional</span>",
    "import.aliasPlaceholder": "super_secret_code123",
    "import.keepLabelTitle": "Guardar nombre de cuenta",
    "import.keepLabelHelp": "El nombre solo se guarda dentro del contenedor cifrado.",
    "import.security": "Solo se extraen <code>shared_secret</code> y, si lo eliges, el nombre de la cuenta. <code>identity_secret</code>, session, revocation code y otros campos se ignoran.",
    "import.submit": "Cifrar y guardar",
    "import.noFileError": "Elige uno o varios maFiles.",
    "import.tooManyFiles": "Puedes subir hasta {max} maFiles a la vez.",
    "import.fileTooLarge": "Cada maFile debe tener 1 MB como máximo.",
    "import.aliasEqualsPrimary": "El código personalizado coincidió con el ID principal. Cambia el código personalizado.",
    "import.aliasMultipleError": "El código personalizado solo se puede usar al subir un maFile.",
    "import.success": "Listo. Los maFiles originales no se enviaron al servidor; en KV solo se guardaron contenedores cifrados.",
    "import.partialSuccess": "Se importaron {success} de {total} maFiles. Revisa las filas con error.",
    "import.error": "No se pudo importar el maFile.",
    "alias.hint.empty": "Opcional. {min}-{max} caracteres; se recomienda una frase larga y única.",
    "alias.hint.valid": "El formato es válido. El código no se enviará al servidor en texto claro.",
    "alias.hint.multi": "El código personalizado solo está disponible al subir un maFile.",
    "validation.aliasLength": "El código personalizado debe tener entre {min} y {max} caracteres.",
    "validation.aliasCharacters": "Usa letras latinas, dígitos y estos símbolos: . _ ~ ! @ # $ % ^ & * + = ? -",
    "validation.accessCodeFormat": "Introduce un ID principal de {primary} caracteres o un código personalizado de al menos {min} caracteres.",
    "mafile.invalidJson": "El archivo no es un maFile JSON válido.",
    "mafile.invalidObject": "maFile debe contener un objeto JSON.",
    "mafile.encryptedUnsupported": "Los maFile SDA cifrados no son compatibles. Descífralo localmente; aquí no tienes que introducir tu contraseña de Steam.",
    "mafile.missingSharedSecret": "No se encontró un shared_secret válido en el maFile.",
    "result.title": "Resultado de importación",
    "result.help": "Guarda los ID principales en un lugar seguro.",
    "result.primaryLabel": "ID principal · 16 caracteres",
    "result.aliasLabel": "Código personalizado",
    "result.warning": "Cualquiera que conozca uno de estos códigos podrá obtener el código Steam Guard. No los envíes por chats ni los guardes en un repositorio público.",
    "auth.kicker": "Authenticator actual",
    "auth.codeLabel": "Código para iniciar sesión en Steam",
    "auth.copyCode": "Copiar código",
    "auth.countdownAria": "Tiempo hasta el siguiente código",
    "auth.countdownLabel": "Actualiza en",
    "auth.note": "El código se calcula localmente con la hora de tu dispositivo. Si el código falla, comprueba la sincronización automática del reloj.",
    "auth.logout": "Cerrar sesión local",
    "auth.seconds": "{count} s",
    "auth.logoutSuccess": "Sesión local borrada.",
    "vault.invalidFormat": "La bóveda descifrada tiene un formato desconocido.",
    "vault.invalidSharedSecret": "El shared_secret descifrado está dañado.",
    "manage.kicker": "Gestión",
    "manage.title": "Código alternativo",
    "manage.description": "Vincula o reemplaza el código personalizado. El ID principal de 16 caracteres seguirá funcionando.",
    "manage.newAliasLabel": "Nuevo código personalizado",
    "manage.newAliasPlaceholder": "my_unique_secret_2026!",
    "manage.bindAlias": "Vincular código",
    "manage.removeAlias": "Desvincular código personalizado",
    "manage.deleteVault": "Eliminar bóveda de KV",
    "manage.aliasOnlyKicker": "Acceso limitado",
    "manage.aliasOnlyTitle": "Entrada con código personalizado",
    "manage.aliasOnlyDescription": "Los códigos Steam Guard están disponibles, pero cambiar el alias o eliminar la bóveda requiere el ID principal.",
    "manage.requirePrimary": "Inicia sesión con el ID principal para cambiar el código.",
    "manage.bindSuccess": "Código personalizado vinculado. En otras regiones de Cloudflare, la actualización de KV puede tardar en aparecer.",
    "manage.bindError": "No se pudo vincular el código.",
    "manage.removeConfirm": "¿Desvincular el código personalizado? El ID principal seguirá funcionando.",
    "manage.removeSuccess": "Código personalizado desvinculado.",
    "manage.removeError": "No se pudo desvincular el código.",
    "manage.deleteConfirm": "¿Eliminar la bóveda cifrada de Cloudflare KV? No se puede deshacer. El maFile guardado localmente no cambiará.",
    "manage.deleteSuccess": "Bóveda eliminada de KV.",
    "manage.deleteError": "No se pudo eliminar la bóveda.",
    "benefits.eyebrow": "<span></span> Por qué SGO (SteamGuardOnline)",
    "benefits.title": "Protección transparente.<br />El control queda en tus manos.",
    "benefits.openTitle": "Totalmente open-source",
    "benefits.openText": "La criptografía del cliente, Pages Function y el modelo de almacenamiento están disponibles para revisión y despliegue propio.",
    "benefits.openLink": "Abrir código fuente",
    "benefits.noLoginTitle": "Sin usuario ni contraseña de Steam",
    "benefits.noLoginText": "El sitio nunca pide credenciales de la cuenta. Para generar el código solo hace falta el <code>shared_secret</code> extraído localmente.",
    "benefits.encryptTitle": "Cifrado antes de enviar",
    "benefits.encryptText": "Cloudflare KV recibe solo ciphertext AES-GCM y una clave envuelta. El descifrado ocurre en tu dispositivo.",
    "benefits.devicesTitle": "Acceso desde varios dispositivos",
    "benefits.devicesText": "El ID principal tiene exactamente 16 caracteres. También puedes vincular tu propio código desde 3 caracteres.",
    "benefits.pinTitle": "PIN para perfiles guardados",
    "benefits.pinText": "La protección con PIN puede activarse para perfiles guardados. Tras 5 intentos erróneos, la bóveda vinculada se elimina de KV.",
    "flow.eyebrow": "<span></span> Cómo funciona",
    "flow.title": "Tu maFile queda<br />bajo protección criptográfica",
    "flow.trigger": "¿Cómo funciona?",
    "flow.text": "El sitio no convierte KV en un almacén de maFiles. Guarda un contenedor cifrado mínimo que solo se puede abrir con el ID principal o el código personalizado vinculado.",
    "flow.step1Title": "Filtrado",
    "flow.step1Text": "El navegador lee JSON y conserva solo shared_secret y un nombre opcional.",
    "flow.step2Title": "Cifrado",
    "flow.step2Text": "Los datos se cifran con una clave AES-256-GCM aleatoria antes de cualquier solicitud de red.",
    "flow.step3Title": "Almacenamiento",
    "flow.step3Text": "KV guarda ciphertext y envolturas de clave separadas para el ID y el alias.",
    "flow.step4Title": "Generación",
    "flow.step4Text": "Tras el descifrado local, el navegador calcula el código Steam Guard de cinco caracteres.",
    "faq.eyebrow": "<span></span> Importante",
    "faq.title": "Seguridad y límites",
    "security.panelAria": "Seguridad y límites",
    "faq.encryptedQuestion": "¿Puedo subir un maFile cifrado?",
    "faq.encryptedAnswer": "Esta versión acepta un maFile JSON normal con el campo <code>shared_secret</code>. No pide la contraseña de cifrado SDA ni la contraseña de Steam. Primero abre el maFile cifrado localmente.",
    "faq.storageQuestion": "¿Se guarda el maFile completo en Cloudflare KV?",
    "faq.storageAnswer": "No. Los campos de trade confirmations, session tokens, revocation code y device data se descartan. Los datos mínimos restantes se cifran con AES-GCM antes de enviarse.",
    "faq.aliasQuestion": "¿Por qué conviene que el código personalizado sea largo?",
    "faq.aliasAnswer": "Es un bearer secret y una clave de descifrado. La interfaz permite códigos desde 3 caracteres, pero un código corto o común puede adivinarse.",
    "faq.cookieQuestion": "¿Dónde se guardan los perfiles?",
    "faq.cookieAnswer": "El PIN para perfiles guardados está activado por defecto, pero puede desactivarse. Con PIN, la cookie guarda una referencia del perfil y la sal, mientras el ID principal o el código personalizado queda cifrado con PIN en KV. Sin PIN, la cookie guarda un device secret. 5 intentos erróneos eliminan la bóveda de KV.",
    "faq.steamQuestion": "¿Esto reemplaza la aplicación oficial de Steam?",
    "faq.steamAnswer": "Técnicamente el sitio genera códigos desde un shared_secret existente, pero guardar el segundo factor online reduce la separación de factores. Para máxima seguridad, usa la aplicación móvil oficial de Steam.",
    "footer.disclaimer": "Proyecto open-source independiente. No está afiliado a Valve Corporation ni a Steam.",
    "footer.source": "Código fuente",
    "unit.kb": "KB",
    "file.selected": "{name} · {size} {unit}",
    "file.selectedMultiple": "{count} archivos · {size} {unit}",
    "api.panelAria": "API del sitio",
    "api.kicker": "Cloudflare Pages Function",
    "api.title": "API del sitio",
    "api.description": "Todas las solicitudes que modifican datos son POST JSON same-origin. Las llamadas API se envían sin cookies; los perfiles guardados se abren con profile id y verifier.",
    "api.endpointsAria": "API endpoints",
    "api.endpoint.health": "Comprueba que API y KV estén listos.",
    "api.endpoint.import": "Crea una bóveda cifrada e índices de acceso.",
    "api.endpoint.lookup": "Devuelve el encrypted payload y la clave envuelta para un lookup token.",
    "api.endpoint.alias": "Vincula, reemplaza o elimina un código personalizado.",
    "api.endpoint.delete": "Elimina la bóveda y los índices vinculados de KV.",
    "api.endpoint.saveSaved": "Guarda un access ID cifrado con PIN para un perfil.",
    "api.endpoint.openSaved": "Comprueba el verifier y devuelve el encrypted access ID.",
    "api.endpoint.deleteSaved": "Elimina el saved profile y la bóveda vinculada.",
    "api.note": "Las respuestas API usan Cache-Control: no-store. Las solicitudes del navegador con Origin externo se rechazan.",
    "api.invalidResponse": "El servidor devolvió una respuesta inválida.",
    "api.requestFailed": "La solicitud falló.",
    "api.lookup.404": "No se encontró la bóveda. Comprueba el código secreto.",
    "api.import.409": "Ese ID o código personalizado ya está en uso.",
    "api.alias.403": "La gestión requiere el ID principal.",
    "api.alias.409": "El código personalizado ya está en uso.",
    "api.delete.403": "Eliminar requiere el ID principal.",
    "api.400": "La solicitud tiene un formato inválido.",
    "api.413": "La solicitud es demasiado grande.",
    "api.415": "Se esperaba Content-Type: application/json.",
    "api.429": "Demasiadas solicitudes. Inténtalo más tarde.",
    "api.503": "El servicio no está disponible temporalmente o KV aún se está configurando.",
  },
  "pt-BR": {
    "meta.title": "SGO (SteamGuardOnline) — Steam Desktop Authenticator online",
    "meta.description": "Steam Desktop Authenticator online e open-source para obter códigos Steam Guard por ID secreto, sem login ou senha da Steam.",
    "language.label": "Idioma",
    "language.aria": "Idioma do site",
    "brand.homeAria": "SGO (SteamGuardOnline) — início",
    "header.projectLinksAria": "Links do projeto",
    "header.infoTabsAria": "Seções de informação",
    "service.checking": "Verificando API…",
    "service.ready": "API e KV prontos",
    "service.warning": "Configuração de KV necessária",
    "hero.eyebrow": "<span></span> Steam Desktop Authenticator online",
    "hero.title": "Códigos Steam Guard<br /><em>em qualquer dispositivo</em>",
    "hero.lead": "Envie um maFile uma vez, salve o ID de 16 caracteres e abra o código atual do Steam Guard em outro computador ou celular. Login e senha da Steam não são necessários.",
    "hero.pointsAria": "Recursos principais",
    "hero.point.encrypt": "maFile é criptografado no navegador",
    "hero.point.noUrl": "O parâmetro id é removido da URL após a leitura",
    "hero.point.noScripts": "Sem scripts de terceiros",
    "vault.kicker": "Cofre criptografado",
    "vault.title": "Abrir ou criar SGO",
    "vault.modeAria": "Modo de trabalho",
    "vault.tab.access": "Obter código",
    "vault.tab.import": "Enviar maFile",
    "vault.tab.security": "Segurança",
    "vault.tab.api": "API",
    "access.panelAria": "Abrir cofre",
    "access.label": "ID principal ou código personalizado",
    "access.placeholder": "Exemplo: super_secret_code123",
    "access.help": "O código é convertido localmente em um token criptográfico. Se um perfil salvo estiver protegido por PIN, o site pedirá o PIN antes de abrir.",
    "access.submit": "Abrir authenticator",
    "access.openSuccess": "Cofre descriptografado localmente no navegador.",
    "access.openError": "Não foi possível abrir o cofre.",
    "profiles.title": "Perfis salvos",
    "profiles.empty": "Ainda não há perfis salvos.",
    "profiles.open": "Abrir",
    "profiles.remove": "Remover",
    "profiles.clear": "Limpar",
    "profiles.clearConfirm": "Excluir todos os perfis salvos do armazenamento deste navegador?",
    "profiles.rememberTitle": "Lembrar perfil neste dispositivo",
    "profiles.rememberHelp": "O perfil fica salvo no armazenamento deste navegador sem expiração. Perfis protegidos por PIN pedirão o PIN ao abrir.",
    "profiles.pinEnabledTitle": "Proteger o perfil salvo com PIN",
    "profiles.pinEnabledHelp": "Se o PIN ficar desativado, o acesso ao armazenamento do navegador poderá abrir o perfil sem um segredo adicional.",
    "profiles.pinLabel": "PIN do perfil",
    "profiles.pinPlaceholder": "3-6",
    "profiles.pinHelp": "O PIN é opcional, mas protege o perfil salvo contra o uso direto dos dados do armazenamento do navegador. 5 tentativas erradas excluem o cofre do KV.",
    "profiles.pinUnlockTitle": "Digite o PIN para {label}",
    "profiles.pinUnlockHelp": "5 tentativas erradas excluem o cofre vinculado do KV.",
    "profiles.pinDisabledWarning": "A proteção por PIN está desativada. A segurança fica menor: se o armazenamento do navegador for acessado, o perfil poderá ser aberto sem PIN.",
    "profiles.pinInvalid": "Digite um PIN de 3 a 6 caracteres imprimíveis.",
    "profiles.rememberImportedTitle": "Adicionar IDs criados aos perfis",
    "profiles.rememberImportedHelp": "Após a importação eles aparecerão na aba de obter código.",
    "profiles.cookieHelp": "Com PIN, o navegador guarda uma referência do perfil e o salt, enquanto o access ID fica criptografado com PIN no KV. Sem PIN, o navegador guarda um device secret. 5 PINs errados excluem o cofre do KV.",
    "profiles.kind.primary": "ID principal",
    "profiles.kind.alias": "Código personalizado",
    "profiles.pinProtected": "PIN",
    "profiles.noPin": "sem PIN",
    "profiles.noPinShort": "sem PIN",
    "profiles.deviceSecretMissing": "Este perfil sem PIN está danificado ou foi criado em outro navegador.",
    "profiles.saved": "Perfil salvo neste dispositivo.",
    "profiles.savedCount": "Perfis salvos: {count}.",
    "profiles.removed": "Perfil removido.",
    "profiles.cleared": "Perfis salvos limpos.",
    "profiles.saveError": "Não foi possível salvar o perfil.",
    "profiles.attemptsLeft": "restam {count}",
    "profiles.pinWrong": "PIN incorreto.",
    "profiles.pinWrongWithAttempts": "PIN incorreto. Tentativas restantes: {count}. Após 5 tentativas erradas, o cofre será excluído do KV.",
    "profiles.deletedAfterAttempts": "O PIN foi digitado incorretamente 5 vezes. O cofre foi excluído do KV e o perfil foi removido do navegador.",
    "profiles.deleteAfterAttemptsError": "Não foi possível excluir o cofre após 5 tentativas de PIN incorretas.",
    "accessKind.primary": "ID principal",
    "accessKind.alias": "Código personalizado",
    "action.show": "Mostrar",
    "action.hide": "Ocultar",
    "action.copy": "Copiar",
    "action.cancel": "Cancelar",
    "busy.processing": "Processando…",
    "busy.decrypting": "Descriptografando…",
    "busy.encrypting": "Criptografando…",
    "busy.binding": "Vinculando…",
    "toast.copied": "Copiado",
    "copy.primary": "ID principal copiado",
    "copy.alias": "Código personalizado copiado",
    "copy.guard": "Código Steam Guard copiado",
    "import.panelAria": "Importar maFile",
    "import.noFile": "Nenhum arquivo selecionado",
    "import.dropTitle": "Solte o maFile aqui",
    "import.dropSubtitle": "ou clique para escolher um ou mais arquivos",
    "import.aliasLabelHtml": "Seu código de acesso <span>opcional</span>",
    "import.aliasPlaceholder": "super_secret_code123",
    "import.keepLabelTitle": "Salvar nome da conta",
    "import.keepLabelHelp": "O nome fica apenas dentro do contêiner criptografado.",
    "import.security": "Apenas <code>shared_secret</code> e, se você escolher, o nome da conta são extraídos. <code>identity_secret</code>, session, revocation code e outros campos são ignorados.",
    "import.submit": "Criptografar e salvar",
    "import.noFileError": "Escolha um ou mais maFiles.",
    "import.tooManyFiles": "Você pode enviar até {max} maFiles por vez.",
    "import.fileTooLarge": "Cada maFile deve ter no máximo 1 MB.",
    "import.aliasEqualsPrimary": "O código personalizado coincidiu com o ID principal. Altere o código personalizado.",
    "import.aliasMultipleError": "O código personalizado só pode ser usado ao enviar um maFile.",
    "import.success": "Pronto. Os maFiles originais não foram enviados ao servidor; apenas contêineres criptografados foram salvos no KV.",
    "import.partialSuccess": "{success} de {total} maFiles importados. Verifique as linhas com erro.",
    "import.error": "Não foi possível importar o maFile.",
    "alias.hint.empty": "Opcional. {min}-{max} caracteres; recomenda-se uma frase longa e única.",
    "alias.hint.valid": "Formato válido. O código não será enviado ao servidor em texto claro.",
    "alias.hint.multi": "O código personalizado só fica disponível ao enviar um maFile.",
    "validation.aliasLength": "O código personalizado deve ter de {min} a {max} caracteres.",
    "validation.aliasCharacters": "Use letras latinas, números e estes símbolos: . _ ~ ! @ # $ % ^ & * + = ? -",
    "validation.accessCodeFormat": "Digite um ID principal de {primary} caracteres ou um código personalizado com pelo menos {min} caracteres.",
    "mafile.invalidJson": "O arquivo não é um maFile JSON válido.",
    "mafile.invalidObject": "maFile deve conter um objeto JSON.",
    "mafile.encryptedUnsupported": "maFiles SDA criptografados não são compatíveis. Descriptografe localmente; não é preciso digitar sua senha da Steam aqui.",
    "mafile.missingSharedSecret": "Nenhum shared_secret válido foi encontrado no maFile.",
    "result.title": "Resultado da importação",
    "result.help": "Salve os IDs principais em um lugar seguro.",
    "result.primaryLabel": "ID principal · 16 caracteres",
    "result.aliasLabel": "Código personalizado",
    "result.warning": "Qualquer pessoa que souber um destes códigos poderá obter o código Steam Guard. Não envie em chats nem armazene em um repositório público.",
    "auth.kicker": "Authenticator atual",
    "auth.codeLabel": "Código para entrar na Steam",
    "auth.copyCode": "Copiar código",
    "auth.countdownAria": "Tempo até o próximo código",
    "auth.countdownLabel": "Atualiza em",
    "auth.note": "O código é calculado localmente usando a hora do seu dispositivo. Se o código estiver incorreto, verifique a sincronização automática do relógio.",
    "auth.logout": "Fechar sessão local",
    "auth.seconds": "{count} s",
    "auth.logoutSuccess": "Sessão local limpa.",
    "vault.invalidFormat": "O cofre descriptografado tem um formato desconhecido.",
    "vault.invalidSharedSecret": "O shared_secret descriptografado está danificado.",
    "manage.kicker": "Gerenciamento",
    "manage.title": "Código alternativo",
    "manage.description": "Vincule ou substitua o código personalizado. O ID principal de 16 caracteres continuará funcionando.",
    "manage.newAliasLabel": "Novo código personalizado",
    "manage.newAliasPlaceholder": "my_unique_secret_2026!",
    "manage.bindAlias": "Vincular código",
    "manage.removeAlias": "Desvincular código personalizado",
    "manage.deleteVault": "Excluir cofre do KV",
    "manage.aliasOnlyKicker": "Acesso limitado",
    "manage.aliasOnlyTitle": "Entrada por código personalizado",
    "manage.aliasOnlyDescription": "Os códigos Steam Guard estão disponíveis, mas alterar o alias ou excluir o cofre exige o ID principal.",
    "manage.requirePrimary": "Entre com o ID principal para alterar o código.",
    "manage.bindSuccess": "Código personalizado vinculado. Em outras regiões da Cloudflare, a atualização do KV pode não aparecer imediatamente.",
    "manage.bindError": "Não foi possível vincular o código.",
    "manage.removeConfirm": "Desvincular o código personalizado? O ID principal continuará funcionando.",
    "manage.removeSuccess": "Código personalizado desvinculado.",
    "manage.removeError": "Não foi possível desvincular o código.",
    "manage.deleteConfirm": "Excluir o cofre criptografado do Cloudflare KV? Não é possível desfazer. O maFile salvo localmente não será alterado.",
    "manage.deleteSuccess": "Cofre excluído do KV.",
    "manage.deleteError": "Não foi possível excluir o cofre.",
    "benefits.eyebrow": "<span></span> Por que SGO (SteamGuardOnline)",
    "benefits.title": "Proteção transparente.<br />O controle fica com você.",
    "benefits.openTitle": "Totalmente open-source",
    "benefits.openText": "A criptografia do cliente, Pages Function e o modelo de armazenamento estão disponíveis para revisão e deploy próprio.",
    "benefits.openLink": "Abrir código-fonte",
    "benefits.noLoginTitle": "Sem login ou senha da Steam",
    "benefits.noLoginText": "O site nunca pede credenciais da conta. Para gerar o código, só é necessário o <code>shared_secret</code> extraído localmente.",
    "benefits.encryptTitle": "Criptografado antes do envio",
    "benefits.encryptText": "Cloudflare KV recebe apenas ciphertext AES-GCM e uma chave encapsulada. A descriptografia acontece no seu dispositivo.",
    "benefits.devicesTitle": "Acesso em vários dispositivos",
    "benefits.devicesText": "O ID principal tem exatamente 16 caracteres. Você também pode vincular seu próprio código a partir de 3 caracteres.",
    "benefits.pinTitle": "PIN para perfis salvos",
    "benefits.pinText": "A proteção por PIN pode ser ativada para perfis salvos. Após 5 tentativas erradas, o cofre vinculado é excluído do KV.",
    "flow.eyebrow": "<span></span> Como funciona",
    "flow.title": "Seu maFile continua<br />protegido por criptografia",
    "flow.trigger": "Como funciona?",
    "flow.text": "O site não transforma KV em um depósito de maFiles. Ele salva um contêiner criptografado mínimo que só pode ser aberto com o ID principal ou um código personalizado vinculado.",
    "flow.step1Title": "Filtragem",
    "flow.step1Text": "O navegador lê o JSON e mantém apenas shared_secret e um nome opcional.",
    "flow.step2Title": "Criptografia",
    "flow.step2Text": "Os dados são criptografados com uma chave AES-256-GCM aleatória antes de qualquer solicitação de rede.",
    "flow.step3Title": "Armazenamento",
    "flow.step3Text": "KV armazena ciphertext e encapsulamentos de chave separados para ID e alias.",
    "flow.step4Title": "Geração",
    "flow.step4Text": "Após a descriptografia local, o navegador calcula o código Steam Guard de cinco caracteres.",
    "faq.eyebrow": "<span></span> Importante",
    "faq.title": "Segurança e limitações",
    "security.panelAria": "Segurança e limitações",
    "faq.encryptedQuestion": "Posso enviar um maFile criptografado?",
    "faq.encryptedAnswer": "Esta versão aceita um maFile JSON comum com o campo <code>shared_secret</code>. Ela não pede a senha de criptografia do SDA nem a senha da Steam. Abra primeiro o maFile criptografado localmente.",
    "faq.storageQuestion": "O maFile completo fica salvo no Cloudflare KV?",
    "faq.storageAnswer": "Não. Campos de trade confirmations, session tokens, revocation code e device data são descartados. Os dados mínimos restantes são criptografados com AES-GCM antes do envio.",
    "faq.aliasQuestion": "Por que é melhor usar um código personalizado longo?",
    "faq.aliasAnswer": "Ele é um bearer secret e uma chave de descriptografia. A interface permite códigos a partir de 3 caracteres, mas um código curto ou comum pode ser adivinhado.",
    "faq.cookieQuestion": "Onde os perfis salvos ficam armazenados?",
    "faq.cookieAnswer": "O PIN para perfis salvos vem ativado por padrão, mas pode ser desativado. Com PIN, o cookie guarda uma referência do perfil e o salt, enquanto o ID principal ou código personalizado fica criptografado com PIN no KV. Sem PIN, o cookie guarda um device secret. 5 tentativas erradas excluem o cofre do KV.",
    "faq.steamQuestion": "Isso substitui o app oficial da Steam?",
    "faq.steamAnswer": "Tecnicamente, o site gera códigos a partir de um shared_secret existente, mas armazenar o segundo fator online reduz a separação dos fatores. Para máxima segurança, use o aplicativo móvel oficial da Steam.",
    "footer.disclaimer": "Projeto open-source independente. Não é afiliado à Valve Corporation nem à Steam.",
    "footer.source": "Código-fonte",
    "unit.kb": "KB",
    "file.selected": "{name} · {size} {unit}",
    "file.selectedMultiple": "{count} arquivos · {size} {unit}",
    "api.panelAria": "API do site",
    "api.kicker": "Cloudflare Pages Function",
    "api.title": "API do site",
    "api.description": "Todas as solicitações que alteram dados são POST JSON same-origin. Chamadas da API são enviadas sem cookies; perfis salvos abrem com profile id e verifier.",
    "api.endpointsAria": "API endpoints",
    "api.endpoint.health": "Verifica se API e KV estão prontos.",
    "api.endpoint.import": "Cria um cofre criptografado e índices de acesso.",
    "api.endpoint.lookup": "Retorna o encrypted payload e a chave encapsulada para um lookup token.",
    "api.endpoint.alias": "Vincula, substitui ou remove um código personalizado.",
    "api.endpoint.delete": "Exclui o cofre e os índices vinculados do KV.",
    "api.endpoint.saveSaved": "Salva um access ID criptografado com PIN para um perfil.",
    "api.endpoint.openSaved": "Verifica o verifier e retorna o encrypted access ID.",
    "api.endpoint.deleteSaved": "Exclui o saved profile e o cofre vinculado.",
    "api.note": "As respostas da API usam Cache-Control: no-store. Solicitações do navegador com Origin externo são rejeitadas.",
    "api.invalidResponse": "O servidor retornou uma resposta inválida.",
    "api.requestFailed": "A solicitação falhou.",
    "api.lookup.404": "Cofre não encontrado. Verifique o código secreto.",
    "api.import.409": "Esse ID ou código personalizado já está em uso.",
    "api.alias.403": "O gerenciamento exige o ID principal.",
    "api.alias.409": "O código personalizado já está em uso.",
    "api.delete.403": "A exclusão exige o ID principal.",
    "api.400": "A solicitação tem formato inválido.",
    "api.413": "A solicitação é grande demais.",
    "api.415": "Esperado Content-Type: application/json.",
    "api.429": "Muitas solicitações. Tente novamente mais tarde.",
    "api.503": "O serviço está temporariamente indisponível ou o KV ainda está sendo configurado.",
  },
};

let currentLanguage = DEFAULT_LANGUAGE;

const state = {
  selectedFiles: [],
  dataKey: null,
  vaultPayload: null,
  primaryToken: null,
  activeAccessCode: null,
  activeAccessToken: null,
  activeSavedProfileId: null,
  pendingSavedProfileId: null,
  accessKind: null,
  hasAlias: false,
  timerId: null,
  currentStep: null,
  pendingStep: null,
  serviceKind: "checking",
  toastTimer: null,
  savedProfiles: [],
  pendingSavedProfilePinIndex: null,
  currentInfoPage: null,
};

class ApiRequestError extends Error {
  constructor(status, message, data = null) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.data = data;
  }
}

function interpolate(template, replacements = {}) {
  return String(template).replace(/\{(\w+)\}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(replacements, key) ? String(replacements[key]) : match,
  );
}

function hasTranslation(key, language = currentLanguage) {
  return Boolean(TRANSLATIONS[language]?.[key] || TRANSLATIONS[DEFAULT_LANGUAGE]?.[key]);
}

function t(key, replacements = {}, fallback = key) {
  const template = TRANSLATIONS[currentLanguage]?.[key] ?? TRANSLATIONS[DEFAULT_LANGUAGE]?.[key] ?? fallback;
  return interpolate(template, replacements);
}

function getInitialLanguage() {
  try {
    const savedLanguage = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (savedLanguage && TRANSLATIONS[savedLanguage]) return savedLanguage;
  } catch {
    // Locale persistence is optional.
  }
  return DEFAULT_LANGUAGE;
}

function setElementText(element, value) {
  const label = element.querySelector("[data-button-label]");
  if (label) {
    label.textContent = value;
  } else {
    element.textContent = value;
  }
}

function validationMessage(validation) {
  const replacements = {
    min: ALIAS_MIN_LENGTH,
    max: ALIAS_MAX_LENGTH,
    primary: 16,
  };

  switch (validation?.reason) {
    case "alias-length":
      return t("validation.aliasLength", replacements, validation.message);
    case "alias-characters":
      return t("validation.aliasCharacters", replacements, validation.message);
    case "access-code-format":
      return t("validation.accessCodeFormat", replacements, validation.message);
    default:
      return validation?.message || t("api.requestFailed");
  }
}

function setServiceStatus(kind) {
  state.serviceKind = kind;
  elements.serviceStatus.textContent = t(`service.${kind}`);
  elements.serviceStatus.dataset.kind = kind;
}

function setAccessKindBadge(kind = "primary") {
  elements.accessKindBadge.textContent = t(kind === "primary" ? "accessKind.primary" : "accessKind.alias");
  elements.accessKindBadge.dataset.kind = kind;
}

function applyAttributeTranslations() {
  for (const element of document.querySelectorAll("[data-i18n-attr]")) {
    const rules = element.dataset.i18nAttr
      .split(";")
      .map((rule) => rule.trim())
      .filter(Boolean);

    for (const rule of rules) {
      const separator = rule.indexOf(":");
      if (separator === -1) continue;
      const attribute = rule.slice(0, separator).trim();
      const key = rule.slice(separator + 1).trim();
      element.setAttribute(attribute, t(key));
    }
  }
}

function applyTranslations() {
  document.documentElement.lang = LANGUAGE_META[currentLanguage]?.htmlLang || LANGUAGE_META[DEFAULT_LANGUAGE].htmlLang;
  if (elements.languageSelect) elements.languageSelect.value = currentLanguage;

  document.title = t("meta.title");
  const description = document.querySelector('meta[name="description"]');
  if (description) description.setAttribute("content", t("meta.description"));

  for (const element of document.querySelectorAll("[data-i18n]")) {
    element.textContent = t(element.dataset.i18n);
  }

  for (const element of document.querySelectorAll("[data-i18n-html]")) {
    element.innerHTML = t(element.dataset.i18nHtml);
  }

  applyAttributeTranslations();
  setServiceStatus(state.serviceKind);
  setSelectedFiles(state.selectedFiles);
  renderSavedProfiles();
  updateRememberPinState();
  updateAliasHint();
  setAccessKindBadge(state.accessKind || "primary");
  syncVisibilityToggle(elements.accessCode, elements.accessVisibility);
  syncVisibilityToggle(elements.customAlias, elements.customAliasVisibility);

  for (const button of document.querySelectorAll("[aria-busy='true'][data-busy-key]")) {
    setElementText(button, t(button.dataset.busyKey));
  }

  if (state.vaultPayload) updateGuardCode();
}

function setLanguage(language) {
  if (!TRANSLATIONS[language]) return;
  currentLanguage = language;
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // Locale persistence is optional.
  }
  applyTranslations();
}

function apiErrorMessage(path, status, serverMessage) {
  const route = path.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const routeKey = `api.${route}.${status}`;
  if (hasTranslation(routeKey)) return t(routeKey);

  const genericKey = `api.${status}`;
  if (hasTranslation(genericKey)) return t(genericKey);

  if (currentLanguage === DEFAULT_LANGUAGE && serverMessage) return serverMessage;
  return t("api.requestFailed");
}

function cookieSecureAttribute() {
  return window.location.protocol === "https:" ? "; Secure" : "";
}

function readCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const cookie = part.trim();
    if (!cookie.startsWith(prefix)) continue;
    return decodeQueryPart(cookie.slice(prefix.length));
  }
  return "";
}

function expireCookie(name) {
  document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=Lax${cookieSecureAttribute()}`;
}

function deleteProfileCookie() {
  expireCookie(PROFILE_COOKIE_NAME);
  expireCookie(PROFILE_COOKIE_CHUNK_COUNT_NAME);
  for (let index = 0; index < PROFILE_COOKIE_MAX_CHUNKS; index += 1) {
    expireCookie(`${PROFILE_COOKIE_CHUNK_PREFIX}${index}`);
  }
}

function deleteSavedProfileStorage() {
  try {
    localStorage.removeItem(PROFILE_STORAGE_KEY);
  } catch {
    // Storage cleanup is best-effort.
  }
  deleteProfileCookie();
}

function safeProfileLabel(value) {
  return String(value || "Steam Guard").replace(/\s+/g, " ").trim().slice(0, 80) || "Steam Guard";
}

function validateProfilePin(pin) {
  const value = String(pin ?? "");
  if (!/^[\x21-\x7e]{3,6}$/.test(value)) {
    return { ok: false, message: t("profiles.pinInvalid") };
  }
  return { ok: true, value };
}

function validateAccessToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function validateSavedProfileId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{24,64}$/.test(value);
}

function validateProfileRecordId(value) {
  return typeof value === "string" && value.length === SAVED_PROFILE_RECORD_ID_LENGTH && /^[A-Za-z0-9_-]+$/.test(value);
}

function validateProfileSalt(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{22}$/.test(value);
}

function validateDeviceSecret(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function profileCookieAttributes() {
  return `Expires=${PROFILE_COOKIE_EXPIRES}; Path=/; SameSite=Lax${cookieSecureAttribute()}`;
}

async function deriveProfilePinMaterial(pin, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`${PROFILE_PIN_SALT_PREFIX}\0${pin}`),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PIN_KDF_ITERATIONS,
    },
    material,
    512,
  );
  const root = new Uint8Array(bits);
  const encryptionBytes = root.slice(0, 32);
  const verifierBytes = root.slice(32, 64);

  try {
    const [encryptionKey, verifierKey] = await Promise.all([
      crypto.subtle.importKey("raw", encryptionBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
      crypto.subtle.importKey("raw", verifierBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    ]);
    const signature = await crypto.subtle.sign("HMAC", verifierKey, PROFILE_PIN_VERIFIER_CONTEXT);
    return { encryptionKey, verifier: toBase64Url(signature) };
  } finally {
    root.fill(0);
    encryptionBytes.fill(0);
    verifierBytes.fill(0);
  }
}

async function encryptAccessCodeForProfile(accessCode, pin) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const { encryptionKey, verifier } = await deriveProfilePinMaterial(pin, salt);
  const plaintext = new TextEncoder().encode(accessCode);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: PROFILE_PIN_AAD, tagLength: 128 },
    encryptionKey,
    plaintext,
  );
  const saltText = toBase64Url(salt);

  return {
    salt: saltText,
    verifier,
    encrypted: {
      v: 1,
      salt: saltText,
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(ciphertext),
    },
  };
}

function normalizeSavedProfileEncrypted(encrypted) {
  if (
    !encrypted ||
    encrypted.v !== 1 ||
    !validateProfileSalt(encrypted.salt) ||
    typeof encrypted.iv !== "string" ||
    typeof encrypted.ciphertext !== "string" ||
    !/^[A-Za-z0-9_-]{16}$/.test(encrypted.iv) ||
    !/^[A-Za-z0-9_-]{24,160}$/.test(encrypted.ciphertext)
  ) {
    throw new Error(t("profiles.pinWrong"));
  }

  return encrypted;
}

async function decryptAccessCodeFromProfile(profile, pin) {
  const salt = fromBase64Url(profile.s);
  const { encryptionKey, verifier } = await deriveProfilePinMaterial(pin, salt);
  const response = await apiPost("/api/open-saved", { id: profile.id, verifier });
  const encrypted = normalizeSavedProfileEncrypted(response.encrypted);
  const iv = fromBase64Url(encrypted.iv);
  const ciphertext = fromBase64Url(encrypted.ciphertext);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: PROFILE_PIN_AAD, tagLength: 128 },
      encryptionKey,
      ciphertext,
    );
  } catch {
    throw new Error(t("profiles.pinWrong"));
  }

  const accessCode = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  const validation = validateAccessCode(accessCode);
  if (!validation.ok) {
    throw new Error(t("profiles.pinWrong"));
  }
  return validation.value;
}

function normalizeSavedProfile(profile) {
  if ((profile?.v !== 3 && profile?.v !== 4) || !validateSavedProfileId(profile?.id) || !validateProfileSalt(profile?.s)) return null;

  const pinProtected = profile.v === 3 ? true : profile.p !== 0;
  const deviceSecret = pinProtected ? null : profile.x;
  if (!pinProtected && !validateDeviceSecret(deviceSecret)) return null;

  const recordId = profile?.r ?? profile?.recordId;
  const savedAt = Number(profile?.t ?? profile?.savedAt);
  const attempts = Number(profile?.a);
  return {
    v: 4,
    id: profile.id,
    s: profile.s,
    ...(validateProfileRecordId(recordId) ? { r: recordId } : {}),
    p: pinProtected ? 1 : 0,
    ...(pinProtected ? {} : { x: deviceSecret }),
    l: safeProfileLabel(profile?.l ?? profile?.label),
    k: profile?.k === "alias" || profile?.kind === "alias" ? "alias" : "primary",
    m: String(profile?.m || "").slice(-4),
    a: Number.isFinite(attempts) ? Math.min(Math.max(0, Math.floor(attempts)), SAVED_PROFILE_MAX_PIN_ATTEMPTS) : 0,
    t: Number.isFinite(savedAt) ? savedAt : Date.now(),
  };
}

function dedupeSavedProfiles(profiles) {
  const seenIds = new Set();
  const seenRecords = new Set();
  const result = [];

  for (const profile of profiles) {
    if (seenIds.has(profile.id)) continue;
    if (profile.r && seenRecords.has(profile.r)) continue;
    seenIds.add(profile.id);
    if (profile.r) seenRecords.add(profile.r);
    result.push(profile);
  }

  return result;
}

function parseSavedProfileCollection(raw) {
  if (!raw) return [];

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(raw)));
    } catch {
      return [];
    }
  }

  const items = Array.isArray(parsed) ? parsed : parsed?.profiles;
  if (!Array.isArray(items)) return [];

  return dedupeSavedProfiles(
    items
      .map(normalizeSavedProfile)
      .filter(Boolean)
      .sort((left, right) => right.t - left.t),
  ).slice(0, SAVED_PROFILE_LIMIT);
}

function loadSavedProfilesFromCookie() {
  const chunkCount = Number(readCookie(PROFILE_COOKIE_CHUNK_COUNT_NAME));
  if (Number.isInteger(chunkCount) && chunkCount > 0 && chunkCount <= PROFILE_COOKIE_MAX_CHUNKS) {
    let payload = "";
    for (let index = 0; index < chunkCount; index += 1) {
      const chunk = readCookie(`${PROFILE_COOKIE_CHUNK_PREFIX}${index}`);
      if (!chunk) {
        payload = "";
        break;
      }
      payload += chunk;
    }

    const chunkedProfiles = parseSavedProfileCollection(payload);
    if (chunkedProfiles.length) return chunkedProfiles;
  }

  return parseSavedProfileCollection(readCookie(PROFILE_COOKIE_NAME));
}

function loadSavedProfilesFromStorage() {
  try {
    const raw = localStorage.getItem(PROFILE_STORAGE_KEY);
    if (raw) {
      return parseSavedProfileCollection(raw);
    }
  } catch {
    // Fall back to the legacy cookie below.
  }

  const migratedProfiles = loadSavedProfilesFromCookie();
  if (migratedProfiles.length) {
    const storedProfiles = writeSavedProfilesToStorage(migratedProfiles);
    if (storedProfiles.length >= migratedProfiles.length) deleteProfileCookie();
    return storedProfiles;
  }
  return [];
}

function writeSavedProfilesToCookie(profiles) {
  const normalized = dedupeSavedProfiles(profiles.map(normalizeSavedProfile).filter(Boolean)).slice(0, SAVED_PROFILE_LIMIT);
  if (!normalized.length) {
    deleteProfileCookie();
    return [];
  }

  const serialized = toBase64Url(new TextEncoder().encode(JSON.stringify(normalized)));
  if (serialized.length <= PROFILE_COOKIE_MAX_BYTES) {
    document.cookie = `${PROFILE_COOKIE_NAME}=${serialized}; ${profileCookieAttributes()}`;
    expireCookie(PROFILE_COOKIE_CHUNK_COUNT_NAME);
    for (let index = 0; index < PROFILE_COOKIE_MAX_CHUNKS; index += 1) {
      expireCookie(`${PROFILE_COOKIE_CHUNK_PREFIX}${index}`);
    }
    return normalized;
  }

  const chunks = [];
  for (let offset = 0; offset < serialized.length; offset += PROFILE_COOKIE_MAX_BYTES) {
    chunks.push(serialized.slice(offset, offset + PROFILE_COOKIE_MAX_BYTES));
  }
  if (chunks.length > PROFILE_COOKIE_MAX_CHUNKS) {
    throw new Error(t("profiles.saveError"));
  }

  expireCookie(PROFILE_COOKIE_NAME);
  document.cookie = `${PROFILE_COOKIE_CHUNK_COUNT_NAME}=${chunks.length}; ${profileCookieAttributes()}`;
  chunks.forEach((chunk, index) => {
    document.cookie = `${PROFILE_COOKIE_CHUNK_PREFIX}${index}=${chunk}; ${profileCookieAttributes()}`;
  });
  for (let index = chunks.length; index < PROFILE_COOKIE_MAX_CHUNKS; index += 1) {
    expireCookie(`${PROFILE_COOKIE_CHUNK_PREFIX}${index}`);
  }
  return normalized;
}

function writeSavedProfilesToStorage(profiles) {
  const normalized = dedupeSavedProfiles(profiles.map(normalizeSavedProfile).filter(Boolean)).slice(0, SAVED_PROFILE_LIMIT);
  if (!normalized.length) {
    deleteSavedProfileStorage();
    return [];
  }

  try {
    localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(normalized));
    deleteProfileCookie();
    return normalized;
  } catch {
    return writeSavedProfilesToCookie(normalized);
  }
}

async function createSavedProfile(profile) {
  const validation = validateAccessCode(profile?.code);
  const usePin = profile?.usePin !== false;
  if (!validation.ok) throw new Error(validationMessage(validation));
  if (!validateAccessToken(profile?.token)) throw new Error(t("profiles.saveError"));

  let secret;
  if (usePin) {
    const pinValidation = validateProfilePin(profile?.pin);
    if (!pinValidation.ok) throw new Error(pinValidation.message);
    secret = pinValidation.value;
  } else {
    secret = toBase64Url(randomBytes(SAVED_PROFILE_DEVICE_SECRET_BYTES));
  }

  const id = validateSavedProfileId(profile?.id) ? profile.id : toBase64Url(randomBytes(SAVED_PROFILE_ID_BYTES));
  const sealed = await encryptAccessCodeForProfile(validation.value, secret);

  await apiPost("/api/save-saved", {
    id,
    accessToken: profile.token,
    verifier: sealed.verifier,
    encrypted: sealed.encrypted,
  });

  return {
    v: 4,
    id,
    s: sealed.salt,
    ...(validateProfileRecordId(profile?.recordId) ? { r: profile.recordId } : {}),
    p: usePin ? 1 : 0,
    ...(usePin ? {} : { x: secret }),
    l: safeProfileLabel(profile?.label),
    k: profile?.kind === "alias" ? "alias" : "primary",
    m: validation.value.slice(-4),
    a: 0,
    t: Date.now(),
  };
}

function mergeSavedProfile(profiles, profile) {
  const normalized = normalizeSavedProfile(profile);
  if (!normalized) return profiles;
  return [
    normalized,
    ...profiles.filter((item) => item.id !== normalized.id && (!normalized.r || item.r !== normalized.r)),
  ].slice(0, SAVED_PROFILE_LIMIT);
}

async function rememberSavedProfiles(profilesToRemember) {
  let profiles = state.savedProfiles.length ? [...state.savedProfiles] : loadSavedProfilesFromStorage();
  const rememberedProfiles = [];

  for (const profile of profilesToRemember) {
    const recordId = validateProfileRecordId(profile?.recordId) ? profile.recordId : "";
    const existingProfile = recordId ? profiles.find((item) => item.r === recordId) : null;
    if (existingProfile) {
      rememberedProfiles.push(existingProfile);
      continue;
    }

    const createdProfile = await createSavedProfile(profile);
    profiles = mergeSavedProfile(profiles, createdProfile);
    profiles = writeSavedProfilesToStorage(profiles);
    const normalized = normalizeSavedProfile(createdProfile);
    const storedProfile = normalized
      ? profiles.find((item) => item.id === normalized.id || (normalized.r && item.r === normalized.r))
      : null;
    if (storedProfile) rememberedProfiles.push(storedProfile);
  }

  state.savedProfiles = writeSavedProfilesToStorage(profiles);
  renderSavedProfiles();
  return rememberedProfiles
    .map((profile) => state.savedProfiles.find((item) => item.id === profile.id || (profile.r && item.r === profile.r)))
    .filter(Boolean);
}

function updateSavedProfileMetadata(id, { recordId, label, kind, mask } = {}) {
  const index = state.savedProfiles.findIndex((profile) => profile.id === id);
  if (index === -1) return;

  const current = state.savedProfiles[index];
  const nextProfile = normalizeSavedProfile({
    ...current,
    ...(validateProfileRecordId(recordId) ? { r: recordId } : {}),
    ...(label ? { l: label } : {}),
    ...(kind === "alias" || kind === "primary" ? { k: kind } : {}),
    ...(mask ? { m: mask } : {}),
    t: Date.now(),
  });
  if (!nextProfile) return;

  state.savedProfiles = writeSavedProfilesToStorage([
    nextProfile,
    ...state.savedProfiles.filter((_, profileIndex) => profileIndex !== index),
  ]);
  renderSavedProfiles();
}

function removeSavedProfile(id) {
  state.savedProfiles = writeSavedProfilesToStorage(state.savedProfiles.filter((profile) => profile.id !== id));
  renderSavedProfiles();
}

function clearSavedProfiles() {
  state.savedProfiles = [];
  deleteSavedProfileStorage();
  renderSavedProfiles();
}

function maskAccessCode(profile) {
  return profile?.m ? `••••${profile.m}` : "••••";
}

function hideSavedProfilePinPanel() {
  state.pendingSavedProfilePinIndex = null;
  elements.savedProfilePinPanel.hidden = true;
  elements.savedProfilePin.value = "";
}

function updateSavedProfilePinPanel({ focus = false, clearValue = false } = {}) {
  const index = state.pendingSavedProfilePinIndex;
  if (!Number.isInteger(index)) {
    elements.savedProfilePinPanel.hidden = true;
    return;
  }

  const profile = state.savedProfiles[index];
  if (!profile || profile.p === 0) {
    hideSavedProfilePinPanel();
    return;
  }

  const label = `${profile.l} · ${maskAccessCode(profile)}`;
  elements.savedProfilePinTitle.textContent = t("profiles.pinUnlockTitle", { label });
  if (clearValue) elements.savedProfilePin.value = "";
  elements.savedProfilePinPanel.hidden = false;
  if (focus) elements.savedProfilePin.focus();
}

function showSavedProfilePinPanel(index, { clearStatus = true } = {}) {
  state.pendingSavedProfilePinIndex = index;
  if (clearStatus) setStatus(elements.savedProfileStatus);
  updateSavedProfilePinPanel({ focus: true, clearValue: true });
}

async function submitSavedProfilePin() {
  const index = state.pendingSavedProfilePinIndex;
  if (!Number.isInteger(index)) return;

  setBusy(elements.savedProfilePinSubmit, true, "busy.decrypting");
  try {
    await openSavedProfile(index, elements.savedProfilePin.value);
  } finally {
    setBusy(elements.savedProfilePinSubmit, false);
  }
}

function renderSavedProfiles() {
  elements.savedProfileList.textContent = "";
  elements.savedProfiles.hidden = state.savedProfiles.length === 0;

  if (!state.savedProfiles.length) {
    hideSavedProfilePinPanel();
    return;
  }

  for (const [index, profile] of state.savedProfiles.entries()) {
    const row = document.createElement("div");
    row.className = "saved-profile-row";

    const details = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = profile.l;
    const meta = document.createElement("span");
    const attemptsLeft = SAVED_PROFILE_MAX_PIN_ATTEMPTS - profile.a;
    const kindText = t(`profiles.kind.${profile.k}`);
    const protectionText = profile.p === 0 ? t("profiles.noPin") : t("profiles.pinProtected");
    meta.textContent =
      profile.a > 0
        ? `${kindText} · ${maskAccessCode(profile)} · ${protectionText} · ${t("profiles.attemptsLeft", { count: attemptsLeft })}`
        : `${kindText} · ${maskAccessCode(profile)} · ${protectionText}`;
    details.append(title, meta);

    const actions = document.createElement("div");
    actions.className = "saved-profile-actions";

    if (profile.p === 0) {
      const noPinLabel = document.createElement("span");
      noPinLabel.className = "profile-no-pin-label";
      noPinLabel.textContent = t("profiles.noPinShort");
      actions.append(noPinLabel);
    }

    const openButton = document.createElement("button");
    openButton.type = "button";
    openButton.className = "copy-button";
    openButton.dataset.profileAction = "open";
    openButton.dataset.profileIndex = String(index);
    openButton.textContent = t("profiles.open");

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "text-button danger";
    removeButton.dataset.profileAction = "remove";
    removeButton.dataset.profileIndex = String(index);
    removeButton.textContent = t("profiles.remove");

    actions.append(openButton, removeButton);
    row.append(details, actions);
    elements.savedProfileList.append(row);
  }

  updateSavedProfilePinPanel();
}

function handleSavedProfilePinFailure(index, error) {
  const profile = state.savedProfiles[index];
  if (!profile) return;

  if (error instanceof ApiRequestError && error.status === 403) {
    if (error.data?.deleted) {
      state.savedProfiles = writeSavedProfilesToStorage(state.savedProfiles.filter((item) => item.id !== profile.id));
      renderSavedProfiles();
      hideSavedProfilePinPanel();
      setStatus(elements.savedProfileStatus, t("profiles.deletedAfterAttempts"), "error");
      return;
    }

    const attemptsLeft = Math.max(0, Number(error.data?.attemptsLeft) || 0);
    const nextProfiles = [...state.savedProfiles];
    nextProfiles[index] = {
      ...profile,
      a: SAVED_PROFILE_MAX_PIN_ATTEMPTS - attemptsLeft,
      t: Date.now(),
    };
    state.savedProfiles = writeSavedProfilesToStorage(nextProfiles);
    renderSavedProfiles();
    showSavedProfilePinPanel(index, { clearStatus: false });
    setStatus(
      elements.savedProfileStatus,
      t("profiles.pinWrongWithAttempts", { count: attemptsLeft }),
      "error",
    );
    return;
  }

  if (error instanceof ApiRequestError && error.status === 404) {
    state.savedProfiles = writeSavedProfilesToStorage(state.savedProfiles.filter((item) => item.id !== profile.id));
    renderSavedProfiles();
    hideSavedProfilePinPanel();
  }

  setStatus(elements.savedProfileStatus, error?.message || t("profiles.pinWrong"), "error");
}

async function openSavedProfile(index, pin) {
  const profile = state.savedProfiles[index];
  if (!profile) return;

  let secret;
  if (profile.p === 0) {
    if (!validateDeviceSecret(profile.x)) {
      setStatus(elements.savedProfileStatus, t("profiles.deviceSecretMissing"), "error");
      return;
    }
    secret = profile.x;
  } else {
    const pinValidation = validateProfilePin(pin);
    if (!pinValidation.ok) {
      setStatus(elements.savedProfileStatus, pinValidation.message, "error");
      return;
    }
    secret = pinValidation.value;
  }

  try {
    const accessCode = await decryptAccessCodeFromProfile(profile, secret);
    const nextProfiles = [...state.savedProfiles];
    nextProfiles[index] = { ...profile, a: 0, t: Date.now() };
    state.savedProfiles = writeSavedProfilesToStorage(nextProfiles);
    renderSavedProfiles();
    setStatus(elements.savedProfileStatus);

    setVaultMode("access");
    updateRememberPinState();
    hideSavedProfilePinPanel();
    elements.accessCode.value = accessCode;
    state.pendingSavedProfileId = profile.id;
    if (typeof elements.accessForm.requestSubmit === "function") {
      elements.accessForm.requestSubmit();
    } else {
      elements.accessForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    }
  } catch (error) {
    handleSavedProfilePinFailure(index, error);
  }
}

function decodeQueryPart(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function splitQueryPart(part) {
  const separator = part.indexOf("=");
  if (separator === -1) return { key: decodeQueryPart(part), value: "" };
  return {
    key: decodeQueryPart(part.slice(0, separator)),
    value: decodeQueryPart(part.slice(separator + 1)),
  };
}

function getAccessCodeFromUrl() {
  const query = window.location.search.slice(1);
  if (!query) return "";

  for (const part of query.split("&")) {
    const { key, value } = splitQueryPart(part);
    if (key === "id") return value;
  }

  return "";
}

function removeAccessCodeFromUrl() {
  const query = window.location.search.slice(1);
  if (!query || !window.history?.replaceState) return;

  const remainingParts = query.split("&").filter((part) => splitQueryPart(part).key !== "id");
  const nextQuery = remainingParts.length ? `?${remainingParts.join("&")}` : "";
  window.history.replaceState(null, "", `${window.location.pathname}${nextQuery}${window.location.hash}`);
}

function submitAccessCodeFromUrl() {
  const accessCode = getAccessCodeFromUrl();
  if (!accessCode) return;

  removeAccessCodeFromUrl();
  setVaultMode("access");
  state.pendingSavedProfileId = null;
  updateRememberPinState();
  elements.accessCode.value = accessCode;

  if (typeof elements.accessForm.requestSubmit === "function") {
    elements.accessForm.requestSubmit();
  } else {
    elements.accessForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  }
}

function setVaultMode(mode) {
  for (const button of elements.vaultModeButtons) {
    const active = button.dataset.vaultMode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  }

  for (const panel of elements.vaultModePanels) {
    panel.hidden = panel.dataset.vaultPanel !== mode;
  }
}

function getInfoPageFromPath() {
  const pathname = window.location.pathname.replace(/\/+$/, "") || "/";
  return INFO_PAGE_BY_PATH.get(pathname) || null;
}

function clearSiteTabSelection() {
  if (elements.siteInfoPanels) elements.siteInfoPanels.hidden = true;

  for (const link of elements.siteTabButtons) {
    link.classList.remove("is-active");
    link.removeAttribute("aria-current");
    if (link.getAttribute("role") === "tab") link.setAttribute("aria-selected", "false");
  }

  for (const panel of elements.siteTabPanels) {
    panel.hidden = true;
  }
}

function setSiteTab(tab, { scroll = true } = {}) {
  const hasPanel = elements.siteTabPanels.some((panel) => panel.dataset.sitePanel === tab);
  if (!hasPanel || !elements.siteInfoPanels) return;

  elements.siteInfoPanels.hidden = false;

  for (const link of elements.siteTabButtons) {
    const active = link.dataset.siteTab === tab;
    link.classList.toggle("is-active", active);
    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
    if (link.getAttribute("role") === "tab") link.setAttribute("aria-selected", String(active));
  }

  for (const panel of elements.siteTabPanels) {
    panel.hidden = panel.dataset.sitePanel !== tab;
  }

  if (scroll) {
    elements.siteInfoPanels.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function applyRouteLayout() {
  const infoPage = getInfoPageFromPath();
  state.currentInfoPage = infoPage;
  document.body.dataset.page = infoPage || "home";

  for (const section of elements.homeSections) {
    section.hidden = Boolean(infoPage);
  }

  if (infoPage) {
    clearActiveVault();
    setSiteTab(infoPage, { scroll: false });
  } else {
    clearSiteTabSelection();
  }
}

function toggleFlowDetails() {
  if (!elements.flowToggle || !elements.flowDetailsPanel) return;

  const expanded = elements.flowToggle.getAttribute("aria-expanded") === "true";
  const nextExpanded = !expanded;
  elements.flowToggle.setAttribute("aria-expanded", String(nextExpanded));
  elements.flowDetailsPanel.hidden = !nextExpanded;

  if (nextExpanded) {
    elements.flowDetailsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

function setStatus(element, message = "", kind = "neutral") {
  element.textContent = message;
  element.dataset.kind = kind;
  element.hidden = !message;
}

function syncVisibilityToggle(input, button) {
  if (!input || !button) return;

  const hidden = input.type === "password";
  const labelKey = hidden ? "action.show" : "action.hide";
  button.setAttribute("aria-pressed", String(!hidden));
  button.setAttribute("aria-label", t(labelKey));
  button.setAttribute("title", t(labelKey));
  button.disabled = input.disabled;

  const showIcon = button.querySelector('[data-visibility-icon="show"]');
  const hideIcon = button.querySelector('[data-visibility-icon="hide"]');
  if (showIcon) showIcon.hidden = !hidden;
  if (hideIcon) hideIcon.hidden = hidden;
}

function togglePasswordVisibility(input, button) {
  if (!input || !button || input.disabled) return;
  input.type = input.type === "password" ? "text" : "password";
  syncVisibilityToggle(input, button);
}

function updateRememberPinState() {
  const importPinEnabled = elements.rememberImportedPinEnabled.checked;
  elements.rememberImportedPin.disabled = !importPinEnabled;
  if (elements.rememberImportedPinField) elements.rememberImportedPinField.hidden = !importPinEnabled;
  if (!importPinEnabled) elements.rememberImportedPin.value = "";
  setStatus(
    elements.rememberImportedPinWarning,
    !importPinEnabled ? t("profiles.pinDisabledWarning") : "",
    "warning",
  );
}

function setBusy(button, busy, busyKey = "busy.processing") {
  if (busy) {
    button.dataset.originalLabel = button.textContent;
    button.dataset.busyKey = busyKey;
    setElementText(button, t(busyKey));
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  } else {
    delete button.dataset.busyKey;
    if (button.dataset.i18n) {
      button.textContent = t(button.dataset.i18n);
    } else {
      const label = button.querySelector("[data-button-label]");
      if (label?.dataset.i18n) {
        label.textContent = t(label.dataset.i18n);
      } else {
        button.textContent = button.dataset.originalLabel || button.textContent;
      }
    }
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  elements.toast.classList.add("is-visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => {
    elements.toast.classList.remove("is-visible");
    setTimeout(() => {
      elements.toast.hidden = true;
    }, 180);
  }, 2200);
}

async function copyText(value, successMessage = t("toast.copied")) {
  try {
    await navigator.clipboard.writeText(value);
    showToast(successMessage);
  } catch {
    const temporary = document.createElement("textarea");
    temporary.value = value;
    temporary.setAttribute("readonly", "");
    temporary.style.position = "fixed";
    temporary.style.opacity = "0";
    document.body.append(temporary);
    temporary.select();
    document.execCommand("copy");
    temporary.remove();
    showToast(successMessage);
  }
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    credentials: "omit",
    cache: "no-store",
    body: JSON.stringify(body),
  });

  let data;
  try {
    data = await response.json();
  } catch {
    throw new ApiRequestError(response.status, t("api.invalidResponse"));
  }

  if (!response.ok) {
    throw new ApiRequestError(response.status, apiErrorMessage(path, response.status, data?.error), data);
  }
  return data;
}

function validateNewAlias(value) {
  return validateAlias(value);
}

function updateAliasHint() {
  if (state.selectedFiles.length > 1) {
    elements.customAlias.disabled = true;
    elements.customAlias.type = "password";
    syncVisibilityToggle(elements.customAlias, elements.customAliasVisibility);
    elements.aliasHint.textContent = t("alias.hint.multi");
    elements.aliasHint.dataset.kind = "neutral";
    return;
  }

  elements.customAlias.disabled = false;
  syncVisibilityToggle(elements.customAlias, elements.customAliasVisibility);
  const value = normalizeAccessCode(elements.customAlias.value);
  if (!value) {
    elements.aliasHint.textContent = t("alias.hint.empty", { min: ALIAS_MIN_LENGTH, max: ALIAS_MAX_LENGTH });
    elements.aliasHint.dataset.kind = "neutral";
    return;
  }

  const validation = validateNewAlias(value);
  elements.aliasHint.textContent = validation.ok ? t("alias.hint.valid") : validationMessage(validation);
  elements.aliasHint.dataset.kind = validation.ok ? "success" : "error";
}

function parseMaFile(text, keepLabel) {
  let parsed;
  try {
    parsed = JSON.parse(text);
    if (typeof parsed === "string") parsed = JSON.parse(parsed);
  } catch {
    throw new Error(t("mafile.invalidJson"));
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(t("mafile.invalidObject"));
  }

  if (parsed.encrypted === true && !parsed.shared_secret) {
    throw new Error(t("mafile.encryptedUnsupported"));
  }

  const sharedSecret = parsed.shared_secret ?? parsed.SharedSecret ?? parsed.maFile?.shared_secret;
  if (typeof sharedSecret !== "string" || !validateSharedSecret(sharedSecret.trim())) {
    throw new Error(t("mafile.missingSharedSecret"));
  }

  let label = null;
  if (keepLabel) {
    const rawLabel = parsed.account_name ?? parsed.accountName ?? parsed.AccountName ?? parsed.maFile?.account_name;
    if (rawLabel !== undefined && rawLabel !== null) {
      label = String(rawLabel).trim().slice(0, 80) || null;
    }
  }

  return {
    v: 1,
    sharedSecret: sharedSecret.trim(),
    label,
    importedAt: new Date().toISOString(),
  };
}

function setSelectedFiles(files) {
  state.selectedFiles = Array.from(files || []);
  if (state.selectedFiles.length > 1) {
    elements.customAlias.value = "";
  }

  if (state.selectedFiles.length === 0) {
    elements.selectedFile.textContent = t("import.noFile");
    elements.fileDrop.classList.remove("has-file");
    updateAliasHint();
    return;
  }

  const totalSizeKb = Math.max(1, Math.round(state.selectedFiles.reduce((sum, file) => sum + file.size, 0) / 1024));
  if (state.selectedFiles.length === 1) {
    const [file] = state.selectedFiles;
    elements.selectedFile.textContent = t("file.selected", { name: file.name, size: totalSizeKb, unit: t("unit.kb") });
  } else {
    elements.selectedFile.textContent = t("file.selectedMultiple", {
      count: state.selectedFiles.length,
      size: totalSizeKb,
      unit: t("unit.kb"),
    });
  }
  elements.fileDrop.classList.add("has-file");
  updateAliasHint();
}

function createImportResultRow({ label, value, copyMessageKey, kind = "success" }) {
  const row = document.createElement("div");
  row.className = "secret-row";
  row.dataset.kind = kind;

  const details = document.createElement("div");
  const labelElement = document.createElement("span");
  labelElement.textContent = label;
  const valueElement = document.createElement("code");
  valueElement.textContent = value;
  details.append(labelElement, valueElement);
  row.append(details);

  if (kind !== "error") {
    const button = document.createElement("button");
    button.className = "copy-button";
    button.type = "button";
    button.textContent = t("action.copy");
    button.dataset.copyValue = value;
    button.dataset.copyMessageKey = copyMessageKey;
    row.append(button);
  }

  return row;
}

function renderImportResults(results) {
  elements.importResultList.textContent = "";

  for (const result of results) {
    const filePrefix = result.fileName ? `${result.fileName} · ` : "";

    if (!result.ok) {
      elements.importResultList.append(
        createImportResultRow({
          label: result.fileName || "maFile",
          value: result.error,
          kind: "error",
        }),
      );
      continue;
    }

    elements.importResultList.append(
      createImportResultRow({
        label: `${filePrefix}${t("result.primaryLabel")}`,
        value: result.primaryCode,
        copyMessageKey: "copy.primary",
      }),
    );

    if (result.alias) {
      elements.importResultList.append(
        createImportResultRow({
          label: `${filePrefix}${t("result.aliasLabel")}`,
          value: result.alias,
          copyMessageKey: "copy.alias",
        }),
      );
    }
  }

  elements.importResult.hidden = results.length === 0;
}

async function importMaFile(file, alias) {
  let encrypted;

  try {
    const fileText = await file.text();
    const filteredPayload = parseMaFile(fileText, elements.keepLabel.checked);
    const primaryCode = randomPrimaryCode();

    if (alias && alias === primaryCode) {
      throw new Error(t("import.aliasEqualsPrimary"));
    }

    encrypted = await createEncryptedPayload(filteredPayload);
    const [primaryEnvelope, aliasEnvelope] = await Promise.all([
      createAccessEnvelope(primaryCode, encrypted.dataKey),
      alias ? createAccessEnvelope(alias, encrypted.dataKey) : Promise.resolve(null),
    ]);

    const importResponse = await apiPost("/api/import", {
      payload: encrypted.payload,
      primary: primaryEnvelope,
      alias: aliasEnvelope,
    });

    const dataKey = encrypted.dataKey;
    encrypted.dataKey = null;
    return {
      ok: true,
      fileName: file.name,
      payload: filteredPayload,
      dataKey,
      primaryCode,
      primaryToken: primaryEnvelope.token,
      alias,
      hasAlias: Boolean(alias),
      recordId: importResponse.recordId,
    };
  } catch (error) {
    if (encrypted?.dataKey instanceof Uint8Array) encrypted.dataKey.fill(0);
    return {
      ok: false,
      fileName: file.name,
      error: error.message || t("import.error"),
    };
  }
}

function validateDecryptedVault(payload) {
  if (!payload || payload.v !== 1 || typeof payload.sharedSecret !== "string") {
    throw new Error(t("vault.invalidFormat"));
  }
  if (!validateSharedSecret(payload.sharedSecret)) {
    throw new Error(t("vault.invalidSharedSecret"));
  }
  return payload;
}

function clearActiveVault({ hide = true } = {}) {
  if (state.timerId) clearInterval(state.timerId);
  state.timerId = null;
  state.currentStep = null;
  state.pendingStep = null;

  if (state.dataKey instanceof Uint8Array) state.dataKey.fill(0);
  state.dataKey = null;
  state.vaultPayload = null;
  state.primaryToken = null;
  state.activeAccessCode = null;
  state.activeAccessToken = null;
  state.activeSavedProfileId = null;
  state.accessKind = null;
  state.hasAlias = false;

  elements.guardCode.textContent = "•••••";
  elements.countdownValue.textContent = "—";
  elements.countdownCircle.style.strokeDashoffset = "100";
  if (hide) elements.authPanel.hidden = true;
}

async function updateGuardCode() {
  if (!state.vaultPayload) return;
  const windowState = steamCodeWindow();

  elements.countdownValue.textContent = t("auth.seconds", { count: windowState.secondsRemaining });
  elements.countdownCircle.style.strokeDashoffset = String(100 * (1 - windowState.remainingFraction));

  if (state.currentStep === windowState.step || state.pendingStep === windowState.step) return;
  state.pendingStep = windowState.step;

  try {
    const code = await generateSteamGuardCode(state.vaultPayload.sharedSecret);
    if (!state.vaultPayload || steamCodeWindow().step !== windowState.step) return;
    elements.guardCode.textContent = code;
    state.currentStep = windowState.step;
  } catch (error) {
    elements.guardCode.textContent = "ERROR";
    setStatus(elements.accessStatus, error.message, "error");
  } finally {
    if (state.pendingStep === windowState.step) state.pendingStep = null;
  }
}

function activateVault({
  payload,
  dataKey,
  kind,
  primaryToken = null,
  hasAlias = false,
  accessCode = null,
  accessToken = null,
  savedProfileId = null,
  scroll = true,
}) {
  clearActiveVault({ hide: false });
  state.vaultPayload = validateDecryptedVault(payload);
  state.dataKey = dataKey;
  state.accessKind = kind;
  state.primaryToken = kind === "primary" ? primaryToken : null;
  state.activeAccessCode = accessCode;
  state.activeAccessToken = accessToken;
  state.activeSavedProfileId = savedProfileId;
  state.hasAlias = Boolean(hasAlias);

  elements.accountLabel.textContent = payload.label || "Steam Guard";
  setAccessKindBadge(kind);
  elements.managePrimary.hidden = kind !== "primary";
  elements.manageAliasOnly.hidden = kind === "primary";
  elements.removeAlias.hidden = !(kind === "primary" && state.hasAlias);
  elements.authPanel.hidden = false;
  elements.aliasForm.reset();
  setStatus(elements.aliasStatus);

  updateGuardCode();
  state.timerId = setInterval(updateGuardCode, 250);
  if (scroll) elements.authPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function handleAccessSubmit(event) {
  event.preventDefault();
  setStatus(elements.accessStatus);

  const validation = validateAccessCode(elements.accessCode.value);
  if (!validation.ok) {
    setStatus(elements.accessStatus, validationMessage(validation), "error");
    elements.accessCode.focus();
    return;
  }

  const accessCode = validation.value;
  let savedProfileId = state.pendingSavedProfileId;
  state.pendingSavedProfileId = null;

  setBusy(elements.accessSubmit, true, "busy.decrypting");
  let prepared;
  let dataKey;

  try {
    prepared = await prepareAccessCode(accessCode);
    const response = await apiPost("/api/lookup", { token: prepared.token });
    dataKey = await unwrapDataKeyWithPreparedAccess(response.wrap, prepared);
    const payload = await decryptEncryptedPayload(response.payload, dataKey);

    if (savedProfileId) {
      updateSavedProfileMetadata(savedProfileId, {
        recordId: response.recordId,
        label: payload.label || "Steam Guard",
        kind: response.kind,
        mask: accessCode.slice(-4),
      });
    } else {
      const [rememberedProfile] = await rememberSavedProfiles([
        {
          code: accessCode,
          token: prepared.token,
          usePin: false,
          label: payload.label || "Steam Guard",
          kind: response.kind,
          recordId: response.recordId,
        },
      ]);
      savedProfileId = rememberedProfile?.id || null;
    }

    activateVault({
      payload,
      dataKey,
      kind: response.kind,
      primaryToken: response.kind === "primary" ? prepared.token : null,
      hasAlias: response.hasAlias,
      accessCode,
      accessToken: prepared.token,
      savedProfileId,
    });
    dataKey = null;
    elements.accessCode.value = "";
    setStatus(elements.accessStatus, t("access.openSuccess"), "success");
  } catch (error) {
    if (dataKey instanceof Uint8Array) dataKey.fill(0);
    setStatus(elements.accessStatus, error.message || t("access.openError"), "error");
  } finally {
    disposePreparedAccess(prepared);
    setBusy(elements.accessSubmit, false);
  }
}

async function handleImportSubmit(event) {
  event.preventDefault();
  setStatus(elements.importStatus);
  elements.importResult.hidden = true;

  const files = state.selectedFiles.length ? state.selectedFiles : Array.from(elements.maFileInput.files || []);
  if (files.length === 0) {
    setStatus(elements.importStatus, t("import.noFileError"), "error");
    return;
  }

  if (files.length > IMPORT_FILE_LIMIT) {
    setStatus(elements.importStatus, t("import.tooManyFiles", { max: IMPORT_FILE_LIMIT }), "error");
    return;
  }

  if (files.some((file) => file.size > 1_000_000)) {
    setStatus(elements.importStatus, t("import.fileTooLarge"), "error");
    return;
  }

  const aliasValue = normalizeAccessCode(elements.customAlias.value);
  if (aliasValue && files.length > 1) {
    setStatus(elements.importStatus, t("import.aliasMultipleError"), "error");
    return;
  }

  let alias = null;
  if (aliasValue) {
    const aliasValidation = validateNewAlias(aliasValue);
    if (!aliasValidation.ok) {
      setStatus(elements.importStatus, validationMessage(aliasValidation), "error");
      elements.customAlias.focus();
      return;
    }
    alias = aliasValidation.value;
  }

  let profilePin = null;
  const useProfilePin = elements.rememberImportedPinEnabled.checked;
  if (useProfilePin) {
    const pinValidation = validateProfilePin(elements.rememberImportedPin.value);
    if (!pinValidation.ok) {
      setStatus(elements.importStatus, pinValidation.message, "error");
      elements.rememberImportedPin.focus();
      return;
    }
    profilePin = pinValidation.value;
  }

  setBusy(elements.importSubmit, true, "busy.encrypting");

  try {
    const results = [];
    for (const file of files) {
      results.push(await importMaFile(file, alias));
    }

    renderImportResults(results);
    const successfulResults = results.filter((result) => result.ok);

    if (successfulResults.length === 0) {
      setStatus(elements.importStatus, results[0]?.error || t("import.error"), "error");
      return;
    }

    const [activeResult, ...inactiveResults] = successfulResults;
    const rememberedProfiles = await rememberSavedProfiles(
      successfulResults.map((result) => ({
        code: result.primaryCode,
        token: result.primaryToken,
        pin: profilePin,
        usePin: useProfilePin,
        label: result.payload.label || result.fileName || "Steam Guard",
        kind: "primary",
        recordId: result.recordId,
      })),
    );
    const activeSavedProfileId =
      rememberedProfiles.find((profile) => profile.r && profile.r === activeResult.recordId)?.id || null;
    setVaultMode("access");
    setStatus(elements.savedProfileStatus, t("profiles.savedCount", { count: rememberedProfiles.length }), "success");

    for (const result of inactiveResults) {
      if (result.dataKey instanceof Uint8Array) result.dataKey.fill(0);
      result.dataKey = null;
    }

    activateVault({
      payload: activeResult.payload,
      dataKey: activeResult.dataKey,
      kind: "primary",
      primaryToken: activeResult.primaryToken,
      hasAlias: activeResult.hasAlias,
      accessCode: activeResult.primaryCode,
      accessToken: activeResult.primaryToken,
      savedProfileId: activeSavedProfileId,
      scroll: files.length === 1,
    });
    activeResult.dataKey = null;

    const statusKey = successfulResults.length === results.length ? "import.success" : "import.partialSuccess";
    setStatus(
      elements.importStatus,
      t(statusKey, { success: successfulResults.length, total: results.length }),
      successfulResults.length === results.length ? "success" : "error",
    );
  } catch (error) {
    setStatus(elements.importStatus, error.message || t("import.error"), "error");
  } finally {
    setBusy(elements.importSubmit, false);
  }
}

async function handleAliasSubmit(event) {
  event.preventDefault();
  setStatus(elements.aliasStatus);

  if (!state.primaryToken || !(state.dataKey instanceof Uint8Array)) {
    setStatus(elements.aliasStatus, t("manage.requirePrimary"), "error");
    return;
  }

  const validation = validateNewAlias(elements.newAlias.value);
  if (!validation.ok) {
    setStatus(elements.aliasStatus, validationMessage(validation), "error");
    return;
  }

  setBusy(elements.aliasSubmit, true, "busy.binding");
  try {
    const envelope = await createAccessEnvelope(validation.value, state.dataKey);
    await apiPost("/api/alias", {
      primaryToken: state.primaryToken,
      alias: envelope,
    });
    state.hasAlias = true;
    elements.removeAlias.hidden = false;
    elements.newAlias.value = "";
    setStatus(elements.aliasStatus, t("manage.bindSuccess"), "success");
  } catch (error) {
    setStatus(elements.aliasStatus, error.message || t("manage.bindError"), "error");
  } finally {
    setBusy(elements.aliasSubmit, false);
  }
}

async function handleRemoveAlias() {
  if (!state.primaryToken) return;
  if (!window.confirm(t("manage.removeConfirm"))) return;

  elements.removeAlias.disabled = true;
  setStatus(elements.aliasStatus);
  try {
    await apiPost("/api/alias", { primaryToken: state.primaryToken, remove: true });
    state.hasAlias = false;
    elements.removeAlias.hidden = true;
    setStatus(elements.aliasStatus, t("manage.removeSuccess"), "success");
  } catch (error) {
    setStatus(elements.aliasStatus, error.message || t("manage.removeError"), "error");
  } finally {
    elements.removeAlias.disabled = false;
  }
}

async function handleDeleteVault() {
  if (!state.primaryToken) return;
  const confirmed = window.confirm(t("manage.deleteConfirm"));
  if (!confirmed) return;

  elements.deleteVault.disabled = true;
  setStatus(elements.aliasStatus);
  try {
    const deletedSavedProfileId = state.activeSavedProfileId;
    await apiPost("/api/delete", { primaryToken: state.primaryToken });
    if (deletedSavedProfileId) {
      try {
        await apiPost("/api/delete-saved", { id: deletedSavedProfileId });
      } catch {
        // The vault is already gone; local profile cleanup below is still useful.
      }
      removeSavedProfile(deletedSavedProfileId);
    }
    clearActiveVault();
    setVaultMode("access");
    setStatus(elements.accessStatus, t("manage.deleteSuccess"), "success");
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (error) {
    setStatus(elements.aliasStatus, error.message || t("manage.deleteError"), "error");
  } finally {
    elements.deleteVault.disabled = false;
  }
}

async function checkService() {
  try {
    const response = await fetch("/api/health", { credentials: "omit", cache: "no-store", headers: { accept: "application/json" } });
    if (!response.ok) throw new Error();
    setServiceStatus("ready");
  } catch {
    setServiceStatus("warning");
  }
}

for (const button of elements.vaultModeButtons) {
  button.addEventListener("click", () => setVaultMode(button.dataset.vaultMode));
}

elements.flowToggle?.addEventListener("click", toggleFlowDetails);

elements.languageSelect.addEventListener("change", () => setLanguage(elements.languageSelect.value));
for (const link of elements.siteTabButtons) {
  link.addEventListener("click", (event) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const tab = link.dataset.siteTab;
    const targetUrl = new URL(link.href, window.location.href);
    const targetPath = targetUrl.pathname.replace(/\/+$/, "") || "/";
    if (!INFO_PAGE_BY_PATH.get(targetPath) || !tab) return;

    event.preventDefault();
    if (window.history?.pushState) {
      window.history.pushState(null, "", `${targetPath}${targetUrl.search}${targetUrl.hash}`);
      applyRouteLayout();
    } else {
      setSiteTab(tab);
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
}
elements.accessForm.addEventListener("submit", handleAccessSubmit);
elements.importForm.addEventListener("submit", handleImportSubmit);
elements.aliasForm.addEventListener("submit", handleAliasSubmit);
elements.customAlias.addEventListener("input", updateAliasHint);
elements.rememberImportedPinEnabled.addEventListener("change", updateRememberPinState);
elements.savedProfileList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-profile-action]");
  if (!button) return;

  const index = Number(button.dataset.profileIndex);
  if (!Number.isInteger(index)) return;

  if (button.dataset.profileAction === "open") {
    const profile = state.savedProfiles[index];
    if (!profile) return;
    if (profile.p !== 0) {
      showSavedProfilePinPanel(index);
      return;
    }
    hideSavedProfilePinPanel();
    openSavedProfile(index, "");
    return;
  }

  const profile = state.savedProfiles[index];
  if (!profile) return;
  hideSavedProfilePinPanel();
  removeSavedProfile(profile.id);
  showToast(t("profiles.removed"));
});
elements.savedProfilePin.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  submitSavedProfilePin();
});
elements.savedProfilePinSubmit.addEventListener("click", submitSavedProfilePin);
elements.savedProfilePinCancel.addEventListener("click", () => {
  hideSavedProfilePinPanel();
  setStatus(elements.savedProfileStatus);
});
elements.clearProfiles.addEventListener("click", () => {
  if (!window.confirm(t("profiles.clearConfirm"))) return;
  clearSavedProfiles();
  hideSavedProfilePinPanel();
  showToast(t("profiles.cleared"));
});
elements.maFileInput.addEventListener("change", () => setSelectedFiles(elements.maFileInput.files || []));
elements.fileDrop.addEventListener("click", () => elements.maFileInput.click());
elements.fileDrop.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    elements.maFileInput.click();
  }
});

for (const eventName of ["dragenter", "dragover"]) {
  elements.fileDrop.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.fileDrop.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.fileDrop.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.fileDrop.classList.remove("is-dragging");
  });
}
elements.fileDrop.addEventListener("drop", (event) => {
  const files = event.dataTransfer?.files || [];
  if (files.length) setSelectedFiles(files);
});

elements.accessVisibility.addEventListener("click", () =>
  togglePasswordVisibility(elements.accessCode, elements.accessVisibility),
);
elements.customAliasVisibility.addEventListener("click", () =>
  togglePasswordVisibility(elements.customAlias, elements.customAliasVisibility),
);

elements.importResultList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy-value]");
  if (!button) return;
  copyText(button.dataset.copyValue, t(button.dataset.copyMessageKey || "toast.copied"));
});
elements.copyGuard.addEventListener("click", () => {
  const code = elements.guardCode.textContent;
  if (/^[A-Z0-9]{5}$/.test(code)) copyText(code, t("copy.guard"));
});
elements.logoutButton.addEventListener("click", () => {
  clearActiveVault();
  setStatus(elements.accessStatus, t("auth.logoutSuccess"), "success");
});
elements.removeAlias.addEventListener("click", handleRemoveAlias);
elements.deleteVault.addEventListener("click", handleDeleteVault);

window.addEventListener("pagehide", () => clearActiveVault());
window.addEventListener("popstate", () => {
  applyRouteLayout();
  if (!state.currentInfoPage) submitAccessCodeFromUrl();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.vaultPayload) updateGuardCode();
});

currentLanguage = getInitialLanguage();
state.savedProfiles = loadSavedProfilesFromStorage();
elements.year.textContent = new Date().getFullYear();
setVaultMode("access");
setSelectedFiles([]);
applyRouteLayout();
applyTranslations();
checkService();
if (!state.currentInfoPage) submitAccessCodeFromUrl();

// Prevent accidental form submission when a copied primary ID is selected.
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !elements.authPanel.hidden) {
    elements.logoutButton.focus();
  }
});

// Keep the import requirement visible for password-manager/autofill tools.
elements.customAlias.setAttribute("minlength", String(ALIAS_MIN_LENGTH));
elements.customAlias.setAttribute("maxlength", String(ALIAS_MAX_LENGTH));
elements.accessCode.setAttribute("data-primary-format", isPrimaryCode(elements.accessCode.value) ? "true" : "false");
