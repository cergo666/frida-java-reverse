Java.perform(() => {
    const MODULES = {
        Cipher: true,
        SecretKeySpec: true,
        IvParameterSpec: true,
        KeyGenerator: false,
        KeyPairGenerator: false,
        MessageDigest: false,
        SecretKeyFactory: false,
        Signature: false,
        Mac: false,
        KeyGenParameterSpec: false,
        KeyStore: false,
        SSLContext: false,
        OkHttp: false,
        EncryptedSharedPrefs: false,
        SQLCipher: false,
        Tink: true,
        AdBlocker: false
    };

    const IGNORE_KEYWORDS = [
        "ads", "admob", "appmetrica",
        "google.analytics", "unity", "ironsource", "adcolony",
        "io.appmetrica.analytics",
        "com.facebook.ads",
        "com.facebook.ads.internal",
        "com.google.android.gms.ads",
        "com.google.android.gms.analytics",
        "com.google.firebase.analytics",
        "com.google.firebase.messaging",
        "com.google.firebase.crashlytics",
        "com.yandex.mobile.ads",
        "com.yandex.appmetrica",
        "com.ironsource",
        "com.applovin",
        "com.unity3d.ads",
        "com.unity3d.services",
        "com.chartboost",
        "com.vungle",
        "com.mbridge",
        "com.inmobi",
        "com.startapp",
        "com.tapjoy",
        "com.adcolony",
        "com.pangle",
        "com.bytedance.sdk.openadsdk",
        "com.kidoz",
        "com.fyber",
        "com.smaato",
        "com.braze",
        "com.appsflyer",
        "com.adjust.sdk",
        "com.kochava",
        "com.branch",
        "com.amplitude",
        "com.mixpanel",
        "com.segment",
        "com.tealium",
        "com.batch",
        "com.onesignal",
        "com.pushwoosh",
        "com.urbanairship",
        "io.branch.referral",
        "net.hockeyapp",
        "com.microsoft.appcenter"
    ];
    const PRINT_STACKTRACE = true;

    const Base64 = Java.use("android.util.Base64");
    const Arrays = Java.use("java.util.Arrays");
    const StringCls = Java.use("java.lang.String");
    const ExceptionCls = Java.use("java.lang.Exception");

    const green = "\x1b[32m", blue = "\x1b[34m", yellow = "\x1b[33m", reset = "\x1b[0m", cyan = "\x1b[36m", magenta = "\x1b[35m", red = "\x1b[31m";
    const ctx = new Map();
    const callCount = new Map();

    let colorIndex = 0;
    const MODULE_COLORS = [green, blue, cyan, magenta, yellow];
    const randomColor = () => {
        colorIndex = (colorIndex + 1) % MODULE_COLORS.length;
        return MODULE_COLORS[colorIndex];
    };

    function encodeBytes(bytes) {
        if (!bytes) return null;
        try {
            const jsStr = StringCls.$new(bytes, "UTF-8") + "";
            return /^[\x20-\x7E\r\n\t]*$/.test(jsStr) && jsStr.length > 0
            ? jsStr
            : Base64.encodeToString(bytes, 0).toString();
        } catch (_) {
            try {
                return Base64.encodeToString(bytes, 0).toString();
            } catch (_) {
                try {
                    return StringCls.$new(bytes) + "";
                } catch (_) {
                    return null;
                }
            }
        }
    }

    function encodeChars(chars) {
        if (!chars) return null;
        try {
            return StringCls.$new(chars) + "";
        } catch (_) {
            return null;
        }
    }

    function bytesToBase64(bytes) {
        if (!bytes) return null;
        try {
            return Base64.getEncoder().encodeToString(bytes);
        } catch (_) {
            return null;
        }
    }

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
        } catch (_) {
            return null;
        }
    }

    function incrementCallCount(method) {
        const count = (callCount.get(method) || 0) + 1;
        callCount.set(method, count);
        return count;
    }

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

    function printBacktrace(stack) {
        console.log(`${cyan}📚 Backtrace (depth: ${stack.length}) ↓↓↓${reset}`);
        stack.slice().reverse().forEach((frame, index) => {
            const indent = '  '.repeat(Math.min(index, 5));
            console.log(`${indent}${magenta}${index + 1}.${reset} ${yellow}${frame.getClassName()}.${green}${frame.getMethodName()}${cyan}(${frame.getFileName()}:${frame.getLineNumber()})${reset}`);
        });
        console.log(`${cyan}📚 [End of Backtrace]${reset}\n`);
    }

    function analyzeStack() {
        const stack = ExceptionCls.$new().getStackTrace();
        let initCount = 0;
        let ignored = false;

        for (let i = 0; i < stack.length; i++) {
            const cls = stack[i].getClassName();
            const mtd = stack[i].getMethodName();
            const fullStr = (cls + "." + mtd).toLowerCase();

            if (!ignored) {
                for (const kw of IGNORE_KEYWORDS) {
                    if (fullStr.includes(kw)) {
                        ignored = true;
                        break;
                    }
                }
            }

            if (cls === "javax.crypto.Cipher" && mtd === "init") {
                initCount++;
            }
        }

        return { ignored, isNested: initCount > 1, stack };
    }

    function extractInputBytes(args) {
        if (!args[0]) return null;

        if (args.length >= 3 && typeof args[1] === "number" && typeof args[2] === "number") {
            const offset = args[1];
            const length = args[2];
            return encodeBytes(Arrays.copyOfRange(args[0], offset, offset + length));
        }
        else if (args.length >= 2 && typeof args[1] === "number") {
            const offset = args[1];
            const length = args[0].length - offset;
            return encodeBytes(Arrays.copyOfRange(args[0], offset, offset + length));
        }
        else {
            return encodeBytes(args[0]);
        }
    }

    function extractOutputBytes(args, result) {
        if (result !== null && result !== undefined && typeof result !== "number") {
            return encodeBytes(result);
        }
        if (typeof result === "number" && args.length >= 4 && args[3]) {
            return encodeBytes(Arrays.copyOfRange(args[3], 0, result));
        }
        return null;
    }

    function logOpmode(opmode) {
        const modes = { 1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP" };
        return modes[opmode] || opmode;
    }

    // ===================== Cipher =====================
    if (MODULES.Cipher) {
        const color = randomColor();

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

                    const op = arguments[0].valueOf();
                    const mode = logOpmode(op);

                    let keyStr = "unknown";
                    try {
                        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                        keyStr = encodeBytes(Java.cast(arguments[1], SecretKeySpec).getEncoded());
                    } catch (_) {
                        try { keyStr = arguments[1].getAlgorithm() + " (non-SecretKeySpec)"; } catch(e) {}
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
                    try { transformation = this.getAlgorithm(); } catch(e) {}

                    const handle = this.hashCode().toString();
                    ctx.set(handle, { transformation, mode });

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
                    const handle = this.hashCode().toString();
                    const c = ctx.get(handle);
                    if (!c || c.mode === undefined) return out;

                    logObj("Cipher.update", {
                        transformation: c.transformation,
                        mode: c.mode,
                        input: extractInputBytes(arguments)
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return out;
                };
            });

            Cipher.doFinal.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    const result = o.apply(this, arguments);
                    const handle = this.hashCode().toString();
                    const c = ctx.get(handle);
                    if (!c || c.mode === undefined) return result;

                    logObj("Cipher.doFinal", {
                        transformation: c.transformation,
                        mode: c.mode,
                        input: extractInputBytes(arguments),
                        output: extractOutputBytes(arguments, result)
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return result;
                };
            });

            if (Cipher.updateAAD) {
                Cipher.updateAAD.overloads.forEach(o => {
                    o.implementation = function () {
                        const analysis = analyzeStack();
                        if (analysis.ignored) return o.apply(this, arguments);

                        const handle = this.hashCode().toString();
                        const c = ctx.get(handle);
                        if (!c || c.mode === undefined) return o.apply(this, arguments);

                        logObj("Cipher.updateAAD", {
                            transformation: c.transformation,
                            mode: c.mode,
                            aad: encodeBytes(arguments[0])
                        }, color);
                        if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                        return o.apply(this, arguments);
                    };
                });
            }
        } catch(e) { console.log(`${red}[!] Cipher hook failed: ${e}${reset}`); }
    }

    // ===================== SecretKeySpec =====================
    if (MODULES.SecretKeySpec) {
        const color = randomColor();
        try {
            const sks = Java.use("javax.crypto.spec.SecretKeySpec");
            sks.$init.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    logObj("SecretKeySpec.$init", {
                        key: encodeBytes(arguments[0]),
                        algorithm: arguments[1]
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SecretKeySpec hook failed: ${e}${reset}`); }
    }

    // ===================== IvParameterSpec =====================
    if (MODULES.IvParameterSpec) {
        const color = randomColor();
        try {
            const ivps = Java.use("javax.crypto.spec.IvParameterSpec");
            ivps.$init.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    logObj("IvParameterSpec.$init", {
                        iv: encodeBytes(arguments[0])
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] IvParameterSpec hook failed: ${e}${reset}`); }
    }

    // ===================== KeyGenerator =====================
    if (MODULES.KeyGenerator) {
        const color = randomColor();
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
                    logObj("KeyGenerator.generateKey", {
                        algorithm: result.getAlgorithm(),
                        key: encodeBytes(result.getEncoded())
                    }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] KeyGenerator hook failed: ${e}${reset}`); }
    }

    // ===================== KeyPairGenerator =====================
    if (MODULES.KeyPairGenerator) {
        const color = randomColor();
        try {
            const kpg = Java.use("java.security.KeyPairGenerator");

            kpg.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyPairGenerator.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyPairGenerator hook failed: ${e}${reset}`); }
    }

    // ===================== MessageDigest =====================
    if (MODULES.MessageDigest) {
        const color = randomColor();
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
                    logObj("MessageDigest.update", {
                        algorithm: this.getAlgorithm(),
                        input: encodeBytes(arguments[0])
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            md.digest.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("MessageDigest.digest", {
                        algorithm: this.getAlgorithm(),
                        output: encodeBytes(result)
                    }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] MessageDigest hook failed: ${e}${reset}`); }
    }

    // ===================== SecretKeyFactory =====================
    if (MODULES.SecretKeyFactory) {
        const color = randomColor();
        try {
            const skf = Java.use("javax.crypto.SecretKeyFactory");

            skf.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SecretKeyFactory.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SecretKeyFactory hook failed: ${e}${reset}`); }
    }

    // ===================== Signature =====================
    if (MODULES.Signature) {
        const color = randomColor();
        try {
            const sig = Java.use("java.security.Signature");

            sig.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Signature.getInstance", { algorithm: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] Signature hook failed: ${e}${reset}`); }
    }

    // ===================== Mac =====================
    if (MODULES.Mac) {
        const color = randomColor();
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
                    logObj("Mac.init", {
                        algorithm: this.getAlgorithm(),
                        key: encodeBytes(arguments[0].getEncoded())
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            mac.doFinal.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("Mac.doFinal", {
                        algorithm: this.getAlgorithm(),
                        input: arguments.length > 0 ? encodeBytes(arguments[0]) : null,
                        output: encodeBytes(result)
                    }, color);
                    return result;
                };
            });
        } catch(e) { console.log(`${red}[!] Mac hook failed: ${e}${reset}`); }
    }

    // ===================== KeyGenParameterSpec =====================
    if (MODULES.KeyGenParameterSpec) {
        const color = randomColor();
        try {
            const kgsBuilder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");

            kgsBuilder.$init.overloads.forEach(o => {
                o.implementation = function () {
                    const purpose = arguments[1];
                    const purposeMap = { 1: "encrypt", 2: "decrypt", 3: "encrypt|decrypt", 4: "sign", 8: "verify" };
                    logObj("KeyGenParameterSpec.$init", {
                        keyStoreAlias: arguments[0],
                        purpose: purposeMap[purpose] || purpose
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            kgsBuilder.setBlockModes.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setBlockModes", { blockModes: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });

            kgsBuilder.setDigests.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setDigests", { digests: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });

            kgsBuilder.setKeySize.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setKeySize", { keySize: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });

            kgsBuilder.setEncryptionPaddings.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyGenParameterSpec.setEncryptionPaddings", { paddings: arguments[0].toString() }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyGenParameterSpec hook failed: ${e}${reset}`); }
    }

    // ===================== KeyStore =====================
    if (MODULES.KeyStore) {
        const color = randomColor();
        try {
            const KeyStore = Java.use("java.security.KeyStore");

            KeyStore.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("KeyStore.getInstance", {
                        type: arguments[0],
                        provider: arguments.length > 1 ? arguments[1] : null
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            KeyStore.load.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    logObj("KeyStore.load", {
                        stream: arguments[0] ? "InputStream" : null,
                        password: arguments[1] ? encodeChars(arguments[1]) : null
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            KeyStore.getEntry.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("KeyStore.getEntry", {
                        alias: arguments[0],
                        password: arguments[1] ? encodeChars(arguments[1]) : null,
                        resultType: result ? result.getClass().getName() : null
                    }, color);
                    return result;
                };
            });

            KeyStore.getKey.overloads.forEach(o => {
                o.implementation = function () {
                    const result = o.apply(this, arguments);
                    logObj("KeyStore.getKey", {
                        alias: arguments[0],
                        password: arguments[1] ? encodeChars(arguments[1]) : null,
                        algorithm: result ? result.getAlgorithm() : null,
                        encoded: result ? encodeBytes(result.getEncoded()) : null
                    }, color);
                    return result;
                };
            });

            KeyStore.setEntry.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    logObj("KeyStore.setEntry", {
                        alias: arguments[0]
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] KeyStore hook failed: ${e}${reset}`); }
    }

    // ===================== SSLContext =====================
    if (MODULES.SSLContext) {
        const color = randomColor();
        try {
            const SSLContext = Java.use("javax.net.ssl.SSLContext");

            SSLContext.getInstance.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SSLContext.getInstance", { protocol: arguments[0] }, color);
                    return o.apply(this, arguments);
                };
            });

            SSLContext.init.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SSLContext.init", {
                        keyManagers: arguments[0] ? arguments[0].length : 0,
                        trustManagers: arguments[1] ? arguments[1].length : null
                    }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(e) { console.log(`${red}[!] SSLContext hook failed: ${e}${reset}`); }

        try {
            const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("TrustManagerImpl.verifyChain", {
                        untrustedChainSize: arguments[0] ? arguments[0].size() : 0
                    }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== OkHttp =====================
    if (MODULES.OkHttp) {
        const color = randomColor();
        try {
            const CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overloads.forEach(o => {
                o.implementation = function () {
                    const analysis = analyzeStack();
                    if (analysis.ignored) return o.apply(this, arguments);

                    logObj("CertificatePinner.check", {
                        hostname: arguments[0],
                        peerCertificates: arguments[1] ? arguments[1].size() : null
                    }, color);
                    if (PRINT_STACKTRACE) printBacktrace(analysis.stack);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}

        try {
            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            OkHttpClient.newBuilder.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("OkHttp.newBuilder", {}, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== EncryptedSharedPreferences =====================
    if (MODULES.EncryptedSharedPrefs) {
        const color = randomColor();
        try {
            const EncryptedSharedPrefs = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
            EncryptedSharedPrefs.create.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("EncryptedSharedPreferences.create", {
                        fileName: arguments[0],
                        masterKeyAlias: arguments[2] ? "MasterKey" : null
                    }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== SQLCipher =====================
    if (MODULES.SQLCipher) {
        const color = randomColor();
        try {
            const SQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");

            SQLiteDatabase.openOrCreateDatabase.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.openOrCreateDatabase", {
                        file: arguments[0],
                        password: arguments[1] ? encodeBytes(arguments[1]) : null
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            SQLiteDatabase.openDatabase.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.openDatabase", {
                        path: arguments[0]
                    }, color);
                    return o.apply(this, arguments);
                };
            });

            SQLiteDatabase.rawExecSQL.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("SQLCipher.rawExecSQL", {
                        sql: arguments[0]
                    }, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== Tink =====================
    if (MODULES.Tink) {
        const color = randomColor();
        try {
            const Aead = Java.use("com.google.crypto.tink.Aead");
            const KeysetHandle = Java.use("com.google.crypto.tink.KeysetHandle");

            KeysetHandle.generateNew.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Tink.KeysetHandle.generateNew", {}, color);
                    return o.apply(this, arguments);
                };
            });

            KeysetHandle.read.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Tink.KeysetHandle.read", {}, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}

        try {
            const Mac = Java.use("com.google.crypto.tink.Mac");
            const KeysetHandle = Java.use("com.google.crypto.tink.KeysetHandle");

            KeysetHandle.getPrimitive.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("Tink.KeysetHandle.getPrimitive", {}, color);
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}
    }

    // ===================== AdBlocker =====================
    if (MODULES.AdBlocker) {
        const color = randomColor();
        console.log(`${yellow}[AdBlocker] Active — blocking ads and spoofing callbacks${reset}`);

        // --- Google AdMob ---
        try {
            const AdView = Java.use("com.google.android.gms.ads.AdView");
            AdView.loadAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.AdView.loadAd", { blocked: true }, color);
                };
            });
            AdView.resume.overloads.forEach(o => {
                o.implementation = function () {};
            });
        } catch(_) {}

        try {
            const InterstitialAd = Java.use("com.google.android.gms.ads.InterstitialAd");
            InterstitialAd.loadAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.InterstitialAd.loadAd", { blocked: true }, color);
                };
            });
            InterstitialAd.show.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.InterstitialAd.show", { blocked: true }, color);
                };
            });
        } catch(_) {}

        try {
            const RewardedAd = Java.use("com.google.android.gms.ads.rewarded.RewardedAd");
            RewardedAd.load.overloads.forEach(o => {
                o.implementation = function (ctx, adUnitId, callback) {
                    logObj("AdBlocker.RewardedAd.load", { adUnitId: adUnitId, blocked: true }, color);
                    if (callback) {
                        const OnAdLoadedListener = Java.use("com.google.android.gms.ads.rewarded.RewardedAdLoadCallback");
                        try {
                            Java.cast(callback, OnAdLoadedListener);
                            callback.onAdLoaded();
                        } catch(_) {}
                    }
                };
            });
        } catch(_) {}

        // --- AdMob Interstitial callback spoofing ---
        try {
            const AdListener = Java.use("com.google.android.gms.ads.AdListener");
            AdListener.onAdLoaded.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.AdListener.onAdLoaded", { spoofed: true }, color);
                };
            });
            AdListener.onAdFailedToLoad.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.AdListener.onAdFailedToLoad", { spoofed: "success" }, color);
                };
            });
        } catch(_) {}

        // --- Facebook Ads ---
        try {
            const FbAdView = Java.use("com.facebook.ads.AdView");
            FbAdView.loadAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.FbAdView.loadAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        try {
            const FbInterstitial = Java.use("com.facebook.ads.InterstitialAd");
            FbInterstitial.loadAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.FbInterstitial.loadAd", { blocked: true }, color);
                };
            });
            FbInterstitial.show.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.FbInterstitial.show", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Unity Ads ---
        try {
            const UnityAds = Java.use("com.unity3d.ads.UnityAds");
            UnityAds.load.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.UnityAds.load", { adUnitId: arguments[0], blocked: true }, color);
                };
            });
            UnityAds.show.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.UnityAds.show", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- IronSource ---
        try {
            const IronSource = Java.use("com.ironsource.mediationsdk.IronSource");
            IronSource.loadInterstitial.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.IronSource.loadInterstitial", { blocked: true }, color);
                };
            });
            IronSource.showInterstitial.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.IronSource.showInterstitial", { blocked: true }, color);
                };
            });
            IronSource.loadRewardedVideo.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.IronSource.loadRewardedVideo", { blocked: true }, color);
                };
            });
            IronSource.showRewardedVideo.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.IronSource.showRewardedVideo", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- AppLovin ---
        try {
            const AppLovin = Java.use("com.applovin.sdk.AppLovinSdk");
            AppLovin.showAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.AppLovin.showAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Vungle ---
        try {
            const Vungle = Java.use("com.vungle.warren.Vungle");
            Vungle.playAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.Vungle.playAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Chartboost ---
        try {
            const Chartboost = Java.use("com.chartboost.sdk.Chartboost");
            Chartboost.showInterstitial.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.Chartboost.showInterstitial", { blocked: true }, color);
                };
            });
            Chartboost.showRewardedVideo.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.Chartboost.showRewardedVideo", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Pangle (TikTok) ---
        try {
            const PangleAd = Java.use("com.bytedance.sdk.openadsdk.TTAdNative");
            PangleAd.loadInterstitialAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.Pangle.loadInterstitialAd", { blocked: true }, color);
                };
            });
            PangleAd.loadRewardVideoAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.Pangle.loadRewardVideoAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- StartApp ---
        try {
            const StartApp = Java.use("com.startapp.sdk.adsbase.StartAppSDK");
            StartApp.showAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.StartApp.showAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Yandex Ads ---
        try {
            const YandexAd = Java.use("com.yandex.mobile.ads.AdView");
            YandexAd.loadAd.overloads.forEach(o => {
                o.implementation = function () {
                    logObj("AdBlocker.YandexAd.loadAd", { blocked: true }, color);
                };
            });
        } catch(_) {}

        // --- Generic WebView ad blocking (intercept URLs) ---
        try {
            const WebView = Java.use("android.webkit.WebView");
            WebView.loadUrl.overloads.forEach(o => {
                o.implementation = function (url) {
                    const urlStr = url.toString().toLowerCase();
                    if (urlStr.includes("ads") || urlStr.includes("admob") ||
                        urlStr.includes("doubleclick") || urlStr.includes("googlesyndication") ||
                        urlStr.includes("facebook.com/tr") || urlStr.includes("analytics")) {
                        logObj("AdBlocker.WebView.loadUrl", { url: urlStr, blocked: true }, color);
                        return;
                    }
                    return o.apply(this, arguments);
                };
            });
        } catch(_) {}

        console.log(`${green}[AdBlocker] Hooked ad networks: AdMob, Facebook, Unity, IronSource, AppLovin, Vungle, Chartboost, Pangle, StartApp, Yandex${reset}`);
    }

    // ===================== Summary =====================
    const enabled = Object.entries(MODULES).filter(([_, v]) => v).map(([k]) => k);
    console.log(`${green}[+] Crypto Hooks installed. Modules: ${enabled.join(", ")}${reset}`);
    console.log(`${green}[+] Ignore list: ${IGNORE_KEYWORDS.length} keywords${reset}`);
    console.log(`${green}[+] PRINT_STACKTRACE: ${PRINT_STACKTRACE}${reset}`);
    console.log(`${green}[+] Call counting enabled${reset}`);
});
