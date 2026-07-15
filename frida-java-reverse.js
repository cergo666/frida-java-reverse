Java.perform(() => {
    // ===================== CONFIGURATION =====================

    const PRINT_STACKTRACE = true;

    const MODULES = {
        Cipher: true,               // javax.crypto.Cipher — отслеживание шифрования/дешифрования
        SecretKeySpec: true,        // javax.crypto.spec.SecretKeySpec — создание секретных ключей
        IvParameterSpec: true,      // javax.crypto.spec.IvParameterSpec — начальные векторы
        KeyGenerator: false,        // javax.crypto.KeyGenerator — генерация ключей
        KeyPairGenerator: false,    // java.security.KeyPairGenerator — генерация пар ключей
        MessageDigest: false,       // java.security.MessageDigest — хеширование
        SecretKeyFactory: false,    // javax.crypto.SecretKeyFactory — создание ключей из данных
        Signature: false,           // java.security.Signature — подпись данных
        Mac: false,                 // javax.crypto.Mac — HMAC и другие коды аутентификации
        KeyGenParameterSpec: false, // android.security.keystore — параметры генерации ключей в KeyStore
        KeyStore: false,            // java.security.KeyStore — хранилище ключей и сертификатов
        SSLContext: false,          // javax.net.ssl.SSLContext — настройка SSL/TLS
        SSLUnpinner: true,          // Обход SSL пиннинга (OkHttp, Conscrypt, WebView, Flutter и др.)
        EncryptedSharedPrefs: false,// androidx.security.crypto — зашифрованные SharedPreferences
        SQLCipher: false,           // net.sqlcipher — зашифрованные SQLite базы данных
        Tink: true,                 // com.google.crypto.tink — криптографическая библиотека Google
        AdBlocker: true             // Блокировка всей рекламы
    };

    // ===================== AD BLOCKER CONSTANTS =====================

    // Рекламные ключевые слова для фильтрации стек-трейсов (анализ вызывающего кода)
    // Используются как подстроки — ловят и полные имена пакетов, и обфусцированные классы
    const AD_KEYWORDS = [
        "adcolony",
        "adjust",
        "adview",
        "amplitude",
        "applovin",
        "appmetrica",
        "appnext",
        "appsflyer",
        "batch",
        "bigo",
        "braze",
        "branch",
        "bytedance",
        "chartboost",
        "facebook.ads",
        "firebase.analytics",
        "firebase.crashlytics",
        "firebase.messaging",
        "fyber",
        "google.ads",
        "google.analytics",
        "gms.ads",
        "hockeyapp",
        "inmobi",
        "ironsource",
        "kidoz",
        "kochava",
        "maticoo",
        "mbridge",
        "microsoft.appcenter",
        "mixpanel",
        "monetization.ads",
        "my.target",
        "onesignal",
        "pangle",
        "pushwoosh",
        "scorp.adsservice",
        "segment",
        "smaato",
        "startapp",
        "tapjoy",
        "tealium",
        "unity.ads",
        "unity.services",
        "urbanairship",
        "vungle",
        "yandex.ads",
        "ads",
        "admob",
        "analytics"
    ];

    // Префиксы классов рекламных Activity для блокировки на уровне Activity
    const AD_ACTIVITY_PREFIXES = [
        "com.applovin.adview.",
        "com.applovin.mediation.",
        "com.applovin.sdk.",
        "com.appnext.ads.",
        "com.bytedance.sdk.openadsdk.activity.",
        "com.chartboost.sdk.",
        "com.facebook.ads.",
        "com.fyber.inneractive.sdk.",
        "com.google.android.gms.ads.",
        "com.inmobi.ads.",
        "com.ironsource.mediationsdk.",
        "com.ironsource.sdk.controller.",
        "com.maticoo.sdk.",
        "com.mbridge.msdk.",
        "com.monetization.ads.",
        "com.startapp.",
        "com.tapjoy.",
        "com.unity3d.ads.",
        "com.unity3d.services.ads.",
        "com.vungle.ads.",
        "com.yandex.mobile.ads.",
        "sg.bigo.ads."
    ];

    // Ключевые слова для блокировки URL в WebView и HttpURLConnection
    const AD_URL_KEYWORDS = [
        "admob",
        "ads",
        "adview",
        "analytics",
        "appmetrica",
        "appnext",
        "applovin",
        "bigo",
        "chartboost",
        "doubleclick",
        "facebook.com/tr",
        "fyber",
        "googlesyndication",
        "inmobi",
        "inneractive",
        "ironsource",
        "maticoo",
        "mbridge",
        "mintegral",
        "mytarget",
        "pangle",
        "startapp",
        "tapjoy",
        "unity3d",
        "vungle",
        "yandex"
    ];

    // ===================== JAVA REFERENCES =====================

    const Base64 = Java.use("android.util.Base64");
    const Arrays = Java.use("java.util.Arrays");
    const StringCls = Java.use("java.lang.String");
    const ExceptionCls = Java.use("java.lang.Exception");

    // ===================== CONSOLE COLORS =====================

    const green   = "\x1b[32m";
    const blue    = "\x1b[34m";
    const yellow  = "\x1b[33m";
    const cyan    = "\x1b[36m";
    const magenta = "\x1b[35m";
    const red     = "\x1b[31m";
    const reset   = "\x1b[0m";

    // ===================== STATE =====================

    const ctx = new Map();          // Cipher контекст: handle -> {transformation, mode}
    const callCount = new Map();    // Счётчик вызовов по имени метода
    let colorIndex = 0;
    const MODULE_COLORS = [green, blue, cyan, magenta, yellow];

    // ===================== UTILITY FUNCTIONS =====================

    // Возвращает следующий цвет из палитры для модуля
    function nextColor() {
        colorIndex = (colorIndex + 1) % MODULE_COLORS.length;
        return MODULE_COLORS[colorIndex];
    }

    // Преобразует байты в UTF-8 строку или Base64 (для бинарных данных)
    function encodeBytes(bytes) {
        if (!bytes) return null;
        try {
            const jsStr = StringCls.$new(bytes, "UTF-8") + "";
            return /^[\x20-\x7E\r\n\t]*$/.test(jsStr) && jsStr.length > 0
                ? jsStr
                : Base64.encodeToString(bytes, 0).toString();
        } catch (_) {
            try { return Base64.encodeToString(bytes, 0).toString(); } catch (_) {
                try { return StringCls.$new(bytes) + ""; } catch (_) { return null; }
            }
        }
    }

    // Преобразует char[] в строку
    function encodeChars(chars) {
        if (!chars) return null;
        try { return StringCls.$new(chars) + ""; } catch (_) { return null; }
    }

    // Конвертирует Base64 в hex-строку
    function base64ToHex(base64) {
        try {
            const bytes = Base64.getDecoder().decode(base64);
            let hex = "";
            for (let i = 0; i < bytes.length; i++) {
                let v = (bytes[i] & 0xff).toString(16);
                if (v.length % 2 === 1) v = "0" + v;
                hex += v;
            }
            return hex;
        } catch (_) { return null; }
    }

    // Инкрементирует и возвращает счётчик вызовов для метода
    function incrementCallCount(method) {
        const count = (callCount.get(method) || 0) + 1;
        callCount.set(method, count);
        return count;
    }

    // Логирует объект с ключ-значениями, автоматически конвертируя Base64 в hex
    function logObj(title, obj, color) {
        const c = color || yellow;
        const count = incrementCallCount(title);
        console.log(`${c}[${title}] #${count}${reset}`);
        for (const [key, val] of Object.entries(obj)) {
            if (val !== null && val !== undefined) {
                console.log(`  ${blue}${key}${reset}: ${green}${val}${reset}`);
                if (key.toLowerCase().includes("base64") || key.toLowerCase().includes("key") || key.toLowerCase().includes("iv")) {
                    const hex = base64ToHex(val);
                    if (hex && [32, 40, 48, 64].includes(hex.length)) {
                        console.log(`  ${blue}${key.replace("Base64", "HEX")}${reset}: ${green}${hex}${reset}`);
                    }
                }
            }
        }
    }

    // Выводит стек-трейс в обратном порядке (от вызывающего кода к корню)
    function printBacktrace(stack) {
        console.log(`${cyan}Backtrace (depth: ${stack.length})${reset}`);
        stack.slice().reverse().forEach((frame, index) => {
            const indent = '  '.repeat(Math.min(index, 5));
            console.log(`${indent}${magenta}${index + 1}.${reset} ${yellow}${frame.getClassName()}.${green}${frame.getMethodName()}${cyan}(${frame.getFileName()}:${frame.getLineNumber()})${reset}`);
        });
        console.log(`${cyan}[End of Backtrace]${reset}\n`);
    }

    // Анализирует стек вызовов: определяет, нужно ли игнорировать (из рекламных SDK)
    // и является ли Cipher.init вложенным вызовом (чтобы не логировать дважды)
    function analyzeStack() {
        const stack = ExceptionCls.$new().getStackTrace();
        let initCount = 0;
        let ignored = false;

        for (let i = 0; i < stack.length; i++) {
            const cls = stack[i].getClassName();
            const mtd = stack[i].getMethodName();
            const fullStr = (cls + "." + mtd).toLowerCase();

            if (!ignored) {
                for (const kw of AD_KEYWORDS) {
                    if (fullStr.includes(kw)) { ignored = true; break; }
                }
            }

            if (cls === "javax.crypto.Cipher" && mtd === "init") {
                initCount++;
            }
        }

        return { ignored, isNested: initCount > 1, stack };
    }

    // Извлекает входные байты из аргументов Cipher (с учётом offset/length)
    function extractInputBytes(args) {
        if (!args[0]) return null;
        if (args.length >= 3 && typeof args[1] === "number" && typeof args[2] === "number") {
            return encodeBytes(Arrays.copyOfRange(args[0], args[1], args[1] + args[2]));
        }
        if (args.length >= 2 && typeof args[1] === "number") {
            return encodeBytes(Arrays.copyOfRange(args[0], args[1], args[0].length));
        }
        return encodeBytes(args[0]);
    }

    // Извлекает выходные байты из результата Cipher
    function extractOutputBytes(args, result) {
        if (result !== null && result !== undefined && typeof result !== "number") {
            return encodeBytes(result);
        }
        if (typeof result === "number" && args.length >= 4 && args[3]) {
            return encodeBytes(Arrays.copyOfRange(args[3], 0, result));
        }
        return null;
    }

    // Конвертирует числовой режим Cipher в читаемую строку
    function logOpmode(opmode) {
        const modes = { 1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP" };
        return modes[opmode] || opmode;
    }

    // Проверяет, содержит ли строка хотя бы одно ключевое слово из списка
    function hasAdKeyword(str, keywords) {
        const lower = str.toLowerCase();
        for (const kw of keywords) {
            if (lower.includes(kw)) return true;
        }
        return false;
    }

    // ===================== CRYPTO HOOKS =====================

    // --- Cipher: отслеживание всех криптографических операций ---
    if (MODULES.Cipher) {
        const color = nextColor();
        try {
            const Cipher = Java.use("javax.crypto.Cipher");

            Cipher.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    const result = o.apply(this, arguments);
                    logObj("Cipher.getInstance", { transformation: arguments[0] }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return result;
                };
            });

            Cipher.init.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored || analysis.isNested) return o.apply(this, arguments);

                    const mode = logOpmode(arguments[0].valueOf());

                    let keyStr = "unknown";
                    try {
                        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                        keyStr = encodeBytes(Java.cast(arguments[1], SecretKeySpec).getEncoded());
                    } catch (_) {
                        try { keyStr = arguments[1].getAlgorithm() + " (non-SecretKeySpec)"; } catch(_) {}
                    }

                    let iv = null, tagLength = null;
                    try {
                        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
                        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                        for (let i = 2; i < arguments.length; i++) {
                            const p = arguments[i];
                            if (!p) continue;
                            if (GCMParameterSpec.class.isInstance(p)) {
                                const g = Java.cast(p, GCMParameterSpec);
                                iv = encodeBytes(g.getIV());
                                tagLength = g.getTLen();
                            } else if (IvParameterSpec.class.isInstance(p)) {
                                iv = encodeBytes(Java.cast(p, IvParameterSpec).getIV());
                            }
                        }
                    } catch(_) {}

                    let transformation = "unknown";
                    try { transformation = this.getAlgorithm(); } catch(_) {}

                    ctx.set(this.hashCode().toString(), { transformation, mode });
                    logObj("Cipher.init", { transformation, mode, key: keyStr, iv, tagLength }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });

            Cipher.update.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    const out = o.apply(this, arguments);
                    const c = ctx.get(this.hashCode().toString());
                    if (!c || c.mode === undefined) return out;
                    logObj("Cipher.update", { transformation: c.transformation, mode: c.mode, input: extractInputBytes(arguments) }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return out;
                };
            });

            Cipher.doFinal.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    const result = o.apply(this, arguments);
                    const c = ctx.get(this.hashCode().toString());
                    if (!c || c.mode === undefined) return result;
                    logObj("Cipher.doFinal", { transformation: c.transformation, mode: c.mode, input: extractInputBytes(arguments), output: extractOutputBytes(arguments, result) }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return result;
                };
            });

            if (Cipher.updateAAD) {
                Cipher.updateAAD.overloads.forEach(o => {
                    o.implementation = function () {
                        const analysis = analyzeStack();
                        if (analysis.ignored) return o.apply(this, arguments);
                        const c = ctx.get(this.hashCode().toString());
                        if (!c || c.mode === undefined) return o.apply(this, arguments);
                        logObj("Cipher.updateAAD", { transformation: c.transformation, mode: c.mode, aad: encodeBytes(arguments[0]) }, color);
                        if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                        return o.apply(this, arguments);
                    };
                });
            }
        } catch(e) { console.log(`${red}[!] Cipher hook failed: ${e}${reset}`); }
    }

    // --- SecretKeySpec: логирование создаваемых секретных ключей ---
    if (MODULES.SecretKeySpec) {
        const color = nextColor();
        try {
            Java.use("javax.crypto.spec.SecretKeySpec").$init.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    logObj("SecretKeySpec.$init", { key: encodeBytes(arguments[0]), algorithm: arguments[1] }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SecretKeySpec hook failed: ${e}${reset}`); }
    }

    // --- IvParameterSpec: логирование начальных векторов ---
    if (MODULES.IvParameterSpec) {
        const color = nextColor();
        try {
            Java.use("javax.crypto.spec.IvParameterSpec").$init.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    logObj("IvParameterSpec.$init", { iv: encodeBytes(arguments[0]) }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] IvParameterSpec hook failed: ${e}${reset}`); }
    }

    // --- KeyGenerator: отслеживание генерации симметричных ключей ---
    if (MODULES.KeyGenerator) {
        const color = nextColor();
        try {
            const kg = Java.use("javax.crypto.KeyGenerator");
            kg.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenerator.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            kg.generateKey.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("KeyGenerator.generateKey", { algorithm: result.getAlgorithm(), key: encodeBytes(result.getEncoded()) }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] KeyGenerator hook failed: ${e}${reset}`); }
    }

    // --- KeyPairGenerator: отслеживание генерации асимметричных ключей ---
    if (MODULES.KeyPairGenerator) {
        const color = nextColor();
        try {
            Java.use("java.security.KeyPairGenerator").getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyPairGenerator.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyPairGenerator hook failed: ${e}${reset}`); }
    }

    // --- MessageDigest: отслеживание хеширования ---
    if (MODULES.MessageDigest) {
        const color = nextColor();
        try {
            const md = Java.use("java.security.MessageDigest");
            md.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("MessageDigest.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            md.update.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("MessageDigest.update", { algorithm: this.getAlgorithm(), input: encodeBytes(arguments[0]) }, color);
                    return o.apply(this, arguments);
                };
            });
            md.digest.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("MessageDigest.digest", { algorithm: this.getAlgorithm(), output: encodeBytes(result) }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] MessageDigest hook failed: ${e}${reset}`); }
    }

    // --- SecretKeyFactory: отслеживание создания ключей из паролей/данных ---
    if (MODULES.SecretKeyFactory) {
        const color = nextColor();
        try {
            Java.use("javax.crypto.SecretKeyFactory").getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SecretKeyFactory.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SecretKeyFactory hook failed: ${e}${reset}`); }
    }

    // --- Signature: отслеживание создания цифровых подписей ---
    if (MODULES.Signature) {
        const color = nextColor();
        try {
            Java.use("java.security.Signature").getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Signature.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] Signature hook failed: ${e}${reset}`); }
    }

    // --- Mac: отслеживание HMAC и других кодов аутентификации ---
    if (MODULES.Mac) {
        const color = nextColor();
        try {
            const mac = Java.use("javax.crypto.Mac");
            mac.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Mac.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            mac.init.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Mac.init", { algorithm: this.getAlgorithm(), key: encodeBytes(arguments[0].getEncoded()) }, color);
                    return o.apply(this, arguments);
                };
            });
            mac.doFinal.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("Mac.doFinal", { algorithm: this.getAlgorithm(), input: arguments.length > 0 ? encodeBytes(arguments[0]) : null, output: encodeBytes(result) }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] Mac hook failed: ${e}${reset}`); }
    }

    // --- KeyGenParameterSpec: отслеживание параметров генерации ключей в Android Keystore ---
    if (MODULES.KeyGenParameterSpec) {
        const color = nextColor();
        try {
            const builder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
            builder.$init.overloads.forEach(o => {
                o.implementation = function () {
                    const purposeMap = { 1: "encrypt", 2: "decrypt", 3: "encrypt|decrypt", 4: "sign", 8: "verify" };
                    logObj("KeyGenParameterSpec.$init", { keyStoreAlias: arguments[0], purpose: purposeMap[arguments[1]] || arguments[1] }, color);
                    return o.apply(this, arguments);
                };
            });
            builder.setBlockModes.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setBlockModes", { blockModes: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });
            builder.setDigests.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setDigests", { digests: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });
            builder.setKeySize.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setKeySize", { keySize: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            builder.setEncryptionPaddings.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setEncryptionPaddings", { paddings: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyGenParameterSpec hook failed: ${e}${reset}`); }
    }

    // --- KeyStore: отслеживание доступа к хранилищу ключей ---
    if (MODULES.KeyStore) {
        const color = nextColor();
        try {
            const KS = Java.use("java.security.KeyStore");
            KS.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyStore.getInstance", { type: arguments[0], provider: arguments.length > 1 ? arguments[1] : null }, color);
                    return o.apply(this, arguments);
                };
            });
            KS.load.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    logObj("KeyStore.load", { stream: arguments[0] ? "InputStream" : null, password: arguments[1] ? encodeChars(arguments[1]) : null }, color);
                    return o.apply(this, arguments);
                };
            });
            KS.getEntry.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("KeyStore.getEntry", { alias: arguments[0], password: arguments[1] ? encodeChars(arguments[1]) : null, resultType: result ? result.getClass().getName() : null }, color);
                    return result;
                };
            });
            KS.getKey.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("KeyStore.getKey", { alias: arguments[0], password: arguments[1] ? encodeChars(arguments[1]) : null, algorithm: result ? result.getAlgorithm() : null, encoded: result ? encodeBytes(result.getEncoded()) : null }, color);
                    return result;
                };
            });
            KS.setEntry.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);
                    logObj("KeyStore.setEntry", { alias: arguments[0] }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyStore hook failed: ${e}${reset}`); }
    }

    // --- SSLContext: отслеживание SSL/TLS соединений и проверки сертификатов ---
    if (MODULES.SSLContext) {
        const color = nextColor();
        try {
            const SSL = Java.use("javax.net.ssl.SSLContext");
            SSL.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SSLContext.getInstance", { protocol: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            SSL.init.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SSLContext.init", { keyManagers: arguments[0] ? arguments[0].length : 0, trustManagers: arguments[1] ? arguments[1].length : null }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SSLContext hook failed: ${e}${reset}`); }
        try {
            Java.use("com.android.org.conscrypt.TrustManagerImpl").verifyChain.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("TrustManagerImpl.verifyChain", { untrustedChainSize: arguments[0] ? arguments[0].size() : 0 }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== SSL UNPINNER =====================

    if (MODULES.SSLUnpinner) {
        const color = nextColor();
        console.log(`${yellow}[SSLUnpinner] Active — bypassing certificate pinning${reset}`);

        // --- TrustManager (Android < 7): подмена на доверяющий всё ---
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const TrustManager = Java.registerClass({
                name: "dev.unpinner.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            const TrustManagers = [TrustManager.$new()];
            const SSLContext_init = Java.use("javax.net.ssl.SSLContext").init.overload(
                "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
            );
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch(_) {}

        // --- TrustManagerImpl (Android > 7): обход проверки цепочки сертификатов ---
        try {
            const ArrayList = Java.use("java.util.ArrayList");
            Java.use("com.android.org.conscrypt.TrustManagerImpl").checkTrustedRecursive.implementation = function() {
                return ArrayList.$new();
            };
        } catch(_) {}
        try {
            Java.use("com.android.org.conscrypt.TrustManagerImpl").verifyChain.implementation = function(untrustedChain) {
                return untrustedChain;
            };
        } catch(_) {}

        // --- OkHttp v3 (4 варианта) ---
        try {
            Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String", "java.util.List").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("okhttp3.CertificatePinner").check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function() {};
        } catch(_) {}

        // --- Squareup CertificatePinner (OkHttp < v3, 2 варианта) ---
        try {
            Java.use("com.squareup.okhttp.CertificatePinner").check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.squareup.okhttp.CertificatePinner").check.overload("java.lang.String", "java.util.List").implementation = function() {};
        } catch(_) {}

        // --- Squareup OkHostnameVerifier (2 варианта) ---
        try {
            Java.use("com.squareup.okhttp.internal.tls.OkHostnameVerifier").verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() { return true; };
        } catch(_) {}
        try {
            Java.use("com.squareup.okhttp.internal.tls.OkHostnameVerifier").verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
        } catch(_) {}

        // --- Trustkit (3 варианта) ---
        try {
            Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier").verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
        } catch(_) {}
        try {
            Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier").verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() { return true; };
        } catch(_) {}
        try {
            Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function() {};
        } catch(_) {}

        // --- OpenSSLSocketImpl Conscrypt (2 варианта) ---
        try {
            Java.use("com.android.org.conscrypt.OpenSSLSocketImpl").verifyCertificateChain.overload("[Ljava.lang.Object;", "java.lang.Object", "java.lang.Object").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.android.org.conscrypt.OpenSSLSocketImpl").verifyCertificateChain.overload("[Ljava.lang.Object;", "java.lang.Object").implementation = function() {};
        } catch(_) {}

        // --- OpenSSLEngineSocketImpl Conscrypt ---
        try {
            Java.use("com.android.org.conscrypt.OpenSSLEngineSocketImpl").verifyCertificateChain.overload("[Ljava.lang.Long;", "java.lang.String").implementation = function() {};
        } catch(_) {}

        // --- OpenSSLSocketImpl Apache Harmony ---
        try {
            Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl").verifyCertificateChain.implementation = function() {};
        } catch(_) {}

        // --- Conscrypt CertPinManager (2 варианта) ---
        try {
            Java.use("com.android.org.conscrypt.CertPinManager").checkChainPinning.overload("java.lang.String", "java.util.List").implementation = function() { return true; };
        } catch(_) {}
        try {
            Java.use("com.android.org.conscrypt.CertPinManager").isChainValid.overload("java.lang.String", "java.util.List").implementation = function() { return true; };
        } catch(_) {}

        // --- CWAC-Netsecurity CertPinManager ---
        try {
            Java.use("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager").isChainValid.overload("java.lang.String", "java.util.List").implementation = function() { return true; };
        } catch(_) {}

        // --- Appcelerator Titanium ---
        try {
            Java.use("appcelerator.https.PinningTrustManager").checkServerTrusted.implementation = function() {};
        } catch(_) {}

        // --- Fabric ---
        try {
            Java.use("io.fabric.sdk.android.services.network.PinningTrustManager").checkServerTrusted.implementation = function() {};
        } catch(_) {}

        // --- PhoneGap ---
        try {
            Java.use("nl.xservices.plugins.sslCertificateChecker").execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function() { return true; };
        } catch(_) {}

        // --- IBM MobileFirst (2 варианта) ---
        try {
            Java.use("com.worklight.wlclient.api.WLClient").getInstance().pinTrustedCertificatePublicKey.overload("java.lang.String").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.worklight.wlclient.api.WLClient").getInstance().pinTrustedCertificatePublicKey.overload("[Ljava.lang.String;").implementation = function() {};
        } catch(_) {}

        // --- IBM WorkLight HostNameVerifierWithCertificatePinning (4 варианта) ---
        try {
            Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning").verify.overload("java.lang.String", "javax.net.ssl.SSLSocket").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning").verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning").verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning").verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
        } catch(_) {}

        // --- Worklight Androidgap ---
        try {
            Java.use("com.worklight.androidgap.plugin.WLCertificatePinningPlugin").execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function() { return true; };
        } catch(_) {}

        // --- Netty FingerprintTrustManagerFactory ---
        try {
            Java.use("io.netty.handler.ssl.util.FingerprintTrustManagerFactory").checkTrusted.implementation = function() {};
        } catch(_) {}

        // --- Chromium Cronet ---
        try {
            const Cronet = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
            Cronet.enablePublicKeyPinningBypassForLocalTrustAnchors.overload("boolean").implementation = function() {
                return Cronet.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
            };
            Cronet.addPublicKeyPins.overload("java.lang.String", "java.util.Set", "boolean", "java.util.Date").implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                return Cronet.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
            };
        } catch(_) {}

        // --- Flutter HttpCertificatePinning ---
        try {
            Java.use("diefferson.http_certificate_pinning.HttpCertificatePinning").checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function() { return true; };
        } catch(_) {}
        try {
            Java.use("com.macif.plugin.sslpinningplugin.SslPinningPlugin").checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function() { return true; };
        } catch(_) {}

        // --- Boye AbstractVerifier ---
        try {
            Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier").verify.implementation = function() {};
        } catch(_) {}

        // --- Apache AbstractVerifier ---
        try {
            Java.use("org.apache.http.conn.ssl.AbstractVerifier").verify.implementation = function() {};
        } catch(_) {}

        // --- Android WebViewClient (4 варианта) ---
        try {
            Java.use("android.webkit.WebViewClient").onReceivedSslError.overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError").implementation = function(view, handler, error) {
                handler.proceed();
            };
        } catch(_) {}
        try {
            Java.use("android.webkit.WebViewClient").onReceivedSslError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("android.webkit.WebViewClient").onReceivedError.overload("android.webkit.WebView", "int", "java.lang.String", "java.lang.String").implementation = function() {};
        } catch(_) {}
        try {
            Java.use("android.webkit.WebViewClient").onReceivedError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function() {};
        } catch(_) {}

        // --- React Native RNCWebViewClient ---
        try {
            Java.use("com.reactnativecommunity.webview.RNCWebViewClient").onReceivedSslError.overload(
                "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
            ).implementation = function(view, handler, error) {
                handler.proceed();
            };
        } catch(_) {}
        try {
            Java.use("com.reactnativecommunity.webview.RNCWebViewClient").onReceivedError.overload(
                "android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError"
            ).implementation = function() {};
        } catch(_) {}

        // --- Apache Cordova WebViewClient ---
        try {
            Java.use("org.apache.cordova.CordovaWebViewClient").onReceivedSslError.overload(
                "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
            ).implementation = function(view, handler, error) {
                handler.proceed();
            };
        } catch(_) {}

        // --- Dynamic SSLPeerUnverifiedException Patcher ---
        function rudimentaryFix(typeName) {
            if (typeName === undefined) return;
            return typeName === "boolean" ? true : null;
        }
        try {
            Java.use("javax.net.ssl.SSLPeerUnverifiedException").$init.implementation = function(str) {
                try {
                    const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                    const exceptionIdx = stackTrace.findIndex(s => s.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException");
                    const caller = stackTrace[exceptionIdx + 1];
                    const cls = Java.use(caller.getClassName());
                    const mtd = cls[caller.getMethodName()];
                    if (mtd.implementation) return this.$init(str);
                    const returnTypeName = mtd.returnType.type;
                    mtd.implementation = function() { return rudimentaryFix(returnTypeName); };
                } catch(_) {}
                return this.$init(str);
            };
        } catch(_) {}

        console.log(`${green}[SSLUnpinner] All bypasses installed${reset}`);
    }

    // --- EncryptedSharedPreferences: отслеживание зашифрованного хранилища ---
    if (MODULES.EncryptedSharedPrefs) {
        const color = nextColor();
        try {
            Java.use("androidx.security.crypto.EncryptedSharedPreferences").create.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("EncryptedSharedPreferences.create", { fileName: arguments[0], masterKeyAlias: arguments[2] ? "MasterKey" : null }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // --- SQLCipher: отслеживание зашифрованных баз данных ---
    if (MODULES.SQLCipher) {
        const color = nextColor();
        try {
            const db = Java.use("net.sqlcipher.database.SQLiteDatabase");
            db.openOrCreateDatabase.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.openOrCreateDatabase", { file: arguments[0], password: arguments[1] ? encodeBytes(arguments[1]) : null }, color);
                    return o.apply(this, arguments);
                };
            });
            db.openDatabase.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.openDatabase", { path: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
            db.rawExecSQL.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.rawExecSQL", { sql: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // --- Tink: отслеживание Google Tink криптографической библиотеки ---
    if (MODULES.Tink) {
        const color = nextColor();
        try {
            const KSH = Java.use("com.google.crypto.tink.KeysetHandle");
            KSH.generateNew.overloads.forEach(o => {
                o.implementation = function () { logObj("Tink.KeysetHandle.generateNew", {}, color); return o.apply(this, arguments); };
            });
            KSH.read.overloads.forEach(o => {
                o.implementation = function () { logObj("Tink.KeysetHandle.read", {}, color); return o.apply(this, arguments); };
            });
            KSH.getPrimitive.overloads.forEach(o => {
                o.implementation = function () { logObj("Tink.KeysetHandle.getPrimitive", {}, color); return o.apply(this, arguments); };
            });
        } catch(_) {}
    }

    // ===================== AD BLOCKER =====================

    if (MODULES.AdBlocker) {
        const color = nextColor();
        console.log(`${yellow}[AdBlocker] Active — blocking ads and spoofing callbacks${reset}`);

        // --- Google AdMob ---
        try {
            const AdView = Java.use("com.google.android.gms.ads.AdView");
            AdView.loadAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.AdMob.loadAd", { blocked: true }, color); };
            });
            AdView.resume.overloads.forEach(o => {
                o.implementation = function () {};
            });
        } catch(_) {}
        try {
            const InterstitialAd = Java.use("com.google.android.gms.ads.InterstitialAd");
            InterstitialAd.loadAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.AdMob.Interstitial.loadAd", { blocked: true }, color); };
            });
            InterstitialAd.show.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.AdMob.Interstitial.show", { blocked: true }, color); };
            });
        } catch(_) {}
        try {
            const RewardedAd = Java.use("com.google.android.gms.ads.rewarded.RewardedAd");
            RewardedAd.load.overloads.forEach(o => {
                o.implementation = function (ctx, adUnitId, callback) {
                    logObj("AdBlocker.AdMob.Rewarded.load", { adUnitId: adUnitId, blocked: true }, color);
                    if (callback) {
                        try {
                            Java.cast(callback, Java.use("com.google.android.gms.ads.rewarded.RewardedAdLoadCallback")).onAdLoaded();
                        } catch(_) {}
                    }
                };
            });
        } catch(_) {}
        try {
            const AdListener = Java.use("com.google.android.gms.ads.AdListener");
            AdListener.onAdLoaded.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.AdMob.AdListener.onAdLoaded", { spoofed: true }, color); };
            });
            AdListener.onAdFailedToLoad.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.AdMob.AdListener.onAdFailedToLoad", { spoofed: "success" }, color); };
            });
        } catch(_) {}

        // --- Facebook Audience Network ---
        try {
            Java.use("com.facebook.ads.AdView").loadAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Facebook.AdView.loadAd", { blocked: true }, color); };
            });
        } catch(_) {}
        try {
            const FbInt = Java.use("com.facebook.ads.InterstitialAd");
            FbInt.loadAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Facebook.Interstitial.loadAd", { blocked: true }, color); };
            });
            FbInt.show.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Facebook.Interstitial.show", { blocked: true }, color); };
            });
        } catch(_) {}
        try {
            const FbRew = Java.use("com.facebook.ads.RewardedVideoAd");
            FbRew.loadAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Facebook.Rewarded.loadAd", { blocked: true }, color); };
            });
            FbRew.show.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Facebook.Rewarded.show", { blocked: true }, color); };
            });
        } catch(_) {}

        // --- Unity Ads ---
        try {
            const Unity = Java.use("com.unity3d.ads.UnityAds");
            Unity.load.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Unity.load", { adUnitId: arguments[0], blocked: true }, color); };
            });
            Unity.show.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.Unity.show", { blocked: true }, color); };
            });
        } catch(_) {}

        // --- IronSource / LevelPlay ---
        try {
            const IS = Java.use("com.ironsource.mediationsdk.IronSource");
            IS.loadInterstitial.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.IronSource.loadInterstitial", { blocked: true }, color); };
            });
            IS.showInterstitial.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.IronSource.showInterstitial", { blocked: true }, color); };
            });
            IS.loadRewardedVideo.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.IronSource.loadRewardedVideo", { blocked: true }, color); };
            });
            IS.showRewardedVideo.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.IronSource.showRewardedVideo", { blocked: true }, color); };
            });
            IS.loadBanner.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.IronSource.loadBanner", { blocked: true }, color); };
            });
        } catch(_) {}

        // --- AppLovin MAX ---
        try { Java.use("com.applovin.sdk.AppLovinSdk").showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const MIA = Java.use("com.applovin.mediation.MaxInterstitialAd"); MIA.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxInterstitial.loadAd", { blocked: true }, color); }; }); MIA.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxInterstitial.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const MRA = Java.use("com.applovin.mediation.MaxRewardedAd"); MRA.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxRewarded.loadAd", { blocked: true }, color); }; }); MRA.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxRewarded.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.applovin.mediation.MaxAdView").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxAdView.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const MOA = Java.use("com.applovin.mediation.MaxAppOpenAd"); MOA.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxAppOpen.loadAd", { blocked: true }, color); }; }); MOA.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppLovin.MaxAppOpen.showAd", { blocked: true }, color); }; }); } catch(_) {}

        // --- Vungle ---
        try {
            const V = Java.use("com.vungle.warren.Vungle");
            V.playAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Vungle.playAd", { blocked: true }, color); }; });
            V.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Vungle.loadAd", { blocked: true }, color); }; });
        } catch(_) {}

        // --- Chartboost ---
        try {
            const CB = Java.use("com.chartboost.sdk.Chartboost");
            CB.showInterstitial.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Chartboost.showInterstitial", { blocked: true }, color); }; });
            CB.showRewardedVideo.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Chartboost.showRewardedVideo", { blocked: true }, color); }; });
            CB.cacheInterstitial.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Chartboost.cacheInterstitial", { blocked: true }, color); }; });
            CB.cacheRewardedVideo.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Chartboost.cacheRewardedVideo", { blocked: true }, color); }; });
        } catch(_) {}

        // --- Pangle (TikTok) ---
        try {
            const PANG = Java.use("com.bytedance.sdk.openadsdk.TTAdNative");
            PANG.loadInterstitialAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Pangle.loadInterstitial", { blocked: true }, color); }; });
            PANG.loadRewardVideoAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Pangle.loadRewardVideo", { blocked: true }, color); }; });
            PANG.loadSplashAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Pangle.loadSplash", { blocked: true }, color); }; });
        } catch(_) {}
        try { Java.use("com.bytedance.sdk.openadsdk.TTInterstitialAd").showInterstitialAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Pangle.showInterstitial", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.bytedance.sdk.openadsdk.TTRewardVideoAd").showRewardVideoAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Pangle.showRewardVideo", { blocked: true }, color); }; }); } catch(_) {}

        // --- StartApp ---
        try { Java.use("com.startapp.sdk.adsbase.StartAppSDK").showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.StartApp.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.startapp.sdk.adsbase.Ad").load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.StartApp.Ad.load", { blocked: true }, color); }; }); } catch(_) {}

        // --- Yandex Mobile Ads ---
        try { Java.use("com.yandex.mobile.ads.AdView").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.AdView.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const YI = Java.use("com.yandex.mobile.ads.interstitial.InterstitialAd"); YI.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.Interstitial.loadAd", { blocked: true }, color); }; }); YI.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.Interstitial.show", { blocked: true }, color); }; }); } catch(_) {}
        try { const YR = Java.use("com.yandex.mobile.ads.rewarded.RewardedAd"); YR.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.Rewarded.loadAd", { blocked: true }, color); }; }); YR.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.Rewarded.show", { blocked: true }, color); }; }); } catch(_) {}
        try { const YO = Java.use("com.yandex.mobile.ads.appopen.AppOpenAd"); YO.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.AppOpen.loadAd", { blocked: true }, color); }; }); YO.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Yandex.AppOpen.show", { blocked: true }, color); }; }); } catch(_) {}

        // --- AppNext ---
        try { const ANI = Java.use("com.appnext.ads.interstitial.Interstitial"); ANI.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppNext.Interstitial.loadAd", { blocked: true }, color); }; }); ANI.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppNext.Interstitial.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.appnext.banners.BannerAd").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppNext.Banner.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const ANF = Java.use("com.appnext.ads.fullscreen.Fullscreen"); ANF.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppNext.Fullscreen.loadAd", { blocked: true }, color); }; }); ANF.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppNext.Fullscreen.showAd", { blocked: true }, color); }; }); } catch(_) {}

        // --- Tapjoy ---
        try { Java.use("com.tapjoy.TapjoyConnect").connect.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Tapjoy.connect", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.tapjoy.TapjoyOfferwall").showOfferwall.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Tapjoy.showOfferwall", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.tapjoy.TapjoyDirect").directAction.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Tapjoy.directAction", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.tapjoy_placement.TapjoyPlacement").requestContent.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Tapjoy.requestContent", { blocked: true }, color); }; }); } catch(_) {}

        // --- Mintegral (mbridge) ---
        try { Java.use("com.mbridge.msdk.MBBridgeSDKManager").init.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.init", { blocked: true }, color); }; }); } catch(_) {}
        try { const MR = Java.use("com.mbridge.mbid.rewarded.RewardAdManager"); MR.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Rewarded.loadAd", { blocked: true }, color); }; }); MR.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Rewarded.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const MI = Java.use("com.mbridge.mbid.interstitial.InterstitialAdManager"); MI.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Interstitial.loadAd", { blocked: true }, color); }; }); MI.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Interstitial.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.mbridge.mbid.banner.BannerAdManager").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Banner.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.mbridge.mbid.splash.SplashAdManager").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Splash.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.mbridge.msdk.reward.bridge.MBRewardBridgeManager").loadReward.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Legacy.RewardBridge.loadReward", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.mbridge.msdk.interstitial.bridge.MBInterstitialBridgeManager").loadInterstitial.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Legacy.InterstitialBridge.load", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.mbridge.msdk.banner.bridge.MBBridgeBannerManager").loadBanner.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Mintegral.Legacy.BridgeBanner.loadBanner", { blocked: true }, color); }; }); } catch(_) {}

        // --- Fyber (Digital Turbine) ---
        try { Java.use("com.fyber.inneractive.sdk.InneractiveAdManager").init.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Fyber.init", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.fyber.inneractive.sdk.InneractiveAdSpot").requestAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Fyber.requestAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.fyber.inneractive.sdk.video.IAVideoAdController").play.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Fyber.Video.play", { blocked: true }, color); }; }); } catch(_) {}

        // --- MyTarget (Mail.ru) ---
        try { const MTI = Java.use("com.my.target.ads.InterstitialAd"); MTI.load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Interstitial.load", { blocked: true }, color); }; }); MTI.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Interstitial.show", { blocked: true }, color); }; }); } catch(_) {}
        try { const MTR = Java.use("com.my.target.ads.RewardVideoAd"); MTR.load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Rewarded.load", { blocked: true }, color); }; }); MTR.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Rewarded.show", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.my.target.ads.Banner320x50").load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Banner320x50.load", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.my.target.nativeads.NativeAd").load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.MyTarget.Native.load", { blocked: true }, color); }; }); } catch(_) {}

        // --- Bigo Ads ---
        try { const BI = Java.use("sg.bigo.ads.api.InterstitialAd"); BI.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Interstitial.loadAd", { blocked: true }, color); }; }); BI.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Interstitial.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const BR = Java.use("sg.bigo.ads.api.RewardVideoAd"); BR.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Rewarded.loadAd", { blocked: true }, color); }; }); BR.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Rewarded.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("sg.bigo.ads.api.BannerAd").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Banner.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("sg.bigo.ads.api.NativeAd").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Native.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("sg.bigo.ads.api.SplashAd").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Bigo.Splash.loadAd", { blocked: true }, color); }; }); } catch(_) {}

        // --- Maticoo ---
        try { const MATI = Java.use("com.maticoo.sdk.core.imp.interstitial.InterstitialAdManager"); MATI.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Interstitial.loadAd", { blocked: true }, color); }; }); MATI.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Interstitial.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { const MATV = Java.use("com.maticoo.sdk.core.imp.video.VideoAdManager"); MATV.loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Video.loadAd", { blocked: true }, color); }; }); MATV.showAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Video.showAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.maticoo.sdk.core.imp.splash.SplashAdManager").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Splash.loadAd", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.maticoo.sdk.core.imp.banner.BannerAdManager").loadAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.Maticoo.Banner.loadAd", { blocked: true }, color); }; }); } catch(_) {}

        // --- InMobi ---
        try { const IMI = Java.use("com.inmobi.ads.InMobiInterstitial"); IMI.load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Interstitial.load", { blocked: true }, color); }; }); IMI.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Interstitial.show", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.inmobi.ads.InMobiBanner").load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Banner.load", { blocked: true }, color); }; }); } catch(_) {}
        try { Java.use("com.inmobi.ads.InMobiNative").load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Native.load", { blocked: true }, color); }; }); } catch(_) {}
        try { const IMR = Java.use("com.inmobi.ads.InMobiRewarded"); IMR.load.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Rewarded.load", { blocked: true }, color); }; }); IMR.show.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.InMobi.Rewarded.show", { blocked: true }, color); }; }); } catch(_) {}

        // --- Internal AdsService (com.scorp.adsservice) ---
        try {
            const AS = Java.use("com.scorp.adsservice.api.AdsService");
            const methods = AS.class.getDeclaredMethods();
            for (let i = 0; i < methods.length; i++) {
                const name = methods[i].getName();
                if (name.startsWith("init") || name.startsWith("show") || name.startsWith("load") ||
                    name === "setCurrentActivity" || name === "setGDPRComplete") {
                    try {
                        AS[name].overloads.forEach(o => {
                            o.implementation = function () {
                                logObj("AdBlocker.InternalAdsService." + name, { blocked: true }, color);
                                if (name.startsWith("show")) return null;
                            };
                        });
                    } catch(_) {}
                }
            }
            console.log(`${green}[AdBlocker] Internal AdsService hooked${reset}`);
        } catch(_) {}

        // --- AppOpenManager ---
        try {
            const AOM = Java.use("com.scorp.adsservice.impl.AppOpenManager");
            AOM.showIfAvailable.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppOpenManager.showIfAvailable", { blocked: true }, color); }; });
            AOM.preloadNextAd.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppOpenManager.preloadNextAd", { blocked: true }, color); }; });
            AOM.onAppOpened.overloads.forEach(o => { o.implementation = function () { logObj("AdBlocker.AppOpenManager.onAppOpened", { blocked: true }, color); }; });
        } catch(_) {}

        // --- LocationRestrictionsManager (rewarded ads for location change) ---
        try {
            Java.use("com.scorp.locationrestrictions.LocationRestrictionsManager").setCurrentLocationAfterAd.overloads.forEach(o => {
                o.implementation = function () { logObj("AdBlocker.LocationRestrictions.setCurrentLocationAfterAd", { blocked: true }, color); };
            });
        } catch(_) {}

        // ==================== ACTIVITY-LEVEL BLOCKING ====================
        // Блокировка рекламных Activity до их создания — предотвращает чёрные экраны
        try {
            Java.use("android.app.Activity").startActivity.overloads.forEach(o => {
                o.implementation = function (intent) {
                    try {
                        const comp = intent.getComponent();
                        if (comp && hasAdKeyword(comp.getClassName(), AD_ACTIVITY_PREFIXES)) {
                            logObj("AdBlocker.ActivityBlocked", { activity: comp.getClassName() }, color);
                            return;
                        }
                    } catch(_) {}
                    return o.apply(this, arguments);
                };
            });
            console.log(`${green}[AdBlocker] Activity-level blocking enabled${reset}`);
        } catch(_) {}

        // ==================== WEBVIEW BLOCKING ====================
        // Блокировка рекламных URL в WebView (file:// пропускаются — это локальные контроллеры SDK)
        try {
            Java.use("android.webkit.WebView").loadUrl.overloads.forEach(o => {
                o.implementation = function (url) {
                    const urlStr = url.toString().toLowerCase();
                    if (!urlStr.startsWith("file://") && hasAdKeyword(urlStr, AD_URL_KEYWORDS)) {
                        logObj("AdBlocker.WebView.loadUrl", { url: urlStr, blocked: true }, color);
                        return;
                    }
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}

        // ==================== NETWORK-LEVEL BLOCKING ====================
        // Блокировка рекламных HTTP-соединений
        try {
            Java.use("java.net.HttpURLConnection").connect.overloads.forEach(o => {
                o.implementation = function () {
                    const url = this.getURL().toString().toLowerCase();
                    if (hasAdKeyword(url, AD_URL_KEYWORDS)) {
                        logObj("AdBlocker.HttpURLConnection.connect", { url: url, blocked: true }, color);
                        return;
                    }
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}

        console.log(`${green}[AdBlocker] All networks hooked: AdMob, Facebook, Unity, IronSource, AppLovin, Vungle, Chartboost, Pangle, StartApp, Yandex, AppNext, Tapjoy, Mintegral, Fyber, MyTarget, Bigo, Maticoo, InMobi + Internal${reset}`);
    }

    // ===================== SUMMARY =====================

    const enabled = Object.entries(MODULES).filter(([_, v]) => v).map(([k]) => k);
    console.log(`${green}[+] Installed modules: ${enabled.join(", ")}${reset}`);
    console.log(`${green}[+] Ad keywords: ${AD_KEYWORDS.length} | Activity prefixes: ${AD_ACTIVITY_PREFIXES.length} | URL keywords: ${AD_URL_KEYWORDS.length}${reset}`);
    console.log(`${green}[+] PRINT_STACKTRACE: ${PRINT_STACKTRACE}${reset}`);
});
