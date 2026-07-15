# frida-java-reverse

Мощный [Frida](https://frida.re) скрипт для реверс-инжиниринга Android-приложений. Перехватывает крипто-операции, анализирует безопасность и блокирует рекламу.

---

## Благодарности

Этот скрипт основан на оригинальном проекте **frida-java-crypto-spy**:

- **Автор оригинала**: [Mehdi Karzari](https://github.com/QM4RS/frida-java-crypto-spy)
- **Telegram**: [@QM4RS](https://t.me/QM4RS)
- **GitHub**: [https://github.com/QM4RS/frida-java-crypto-spy](https://github.com/QM4RS/frida-java-crypto-spy)

Оригинальный скрипт предоставлял базовый перехват `javax.crypto.Cipher` с логированием ключей, IV и данных.

SSL Unpinner основан на https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/ от Maurizio Siddu.

---

## Быстрый старт

```bash
frida -U -f target.app.package -l frida-java-reverse.js
```

---

## Конфигурация

В начале файла `frida-java-reverse.js` находятся настройки:

```javascript
const PRINT_STACKTRACE = true;

const MODULES = {
    Cipher: true,               // javax.crypto.Cipher
    SecretKeySpec: true,        // javax.crypto.spec.SecretKeySpec
    IvParameterSpec: true,      // javax.crypto.spec.IvParameterSpec
    KeyGenerator: false,        // javax.crypto.KeyGenerator
    KeyPairGenerator: false,    // java.security.KeyPairGenerator
    MessageDigest: false,       // java.security.MessageDigest
    SecretKeyFactory: false,    // javax.crypto.SecretKeyFactory
    Signature: false,           // java.security.Signature
    Mac: false,                 // javax.crypto.Mac
    KeyGenParameterSpec: false, // android.security.keystore
    KeyStore: false,            // java.security.KeyStore
    SSLContext: false,          // javax.net.ssl.SSLContext
    SSLUnpinner: true,          // Обход SSL пиннинга (OkHttp, Conscrypt, WebView, Flutter и др.)
    EncryptedSharedPrefs: false,// androidx.security.crypto
    SQLCipher: false,           // net.sqlcipher
    Tink: true,                 // com.google.crypto.tink
    AdBlocker: true             // Блокировка всей рекламы
};
```

---

## PRINT_STACKTRACE

Глобальный переключатель в начале файла. При `true` к каждому перехваченному вызову добавляется стек-трейс (backtrace) с указанием глубины и пути вызова — от Java-метода до точки входа в приложение. При `false` выводятся только данные вызова (ключ, IV, данные) без стека.

---

## Модули

### Включены по умолчанию

| Модуль | Описание |
|--------|----------|
| `Cipher` | Перехват шифрования/дешифрования (AES, DES, RSA и др.) |
| `SecretKeySpec` | Прямой перехват создания ключей |
| `IvParameterSpec` | Перехват вектора инициализации |
| `Tink` | Перехват Google Tink крипто-библиотеки |
| `SSLUnpinner` | Обход SSL пиннинга (27 методов bypass) |
| `AdBlocker` | Блокировка рекламы + подавление рекламного шума в крипто-логах |

### Выключены по умолчанию

| Модуль | Описание |
|--------|----------|
| `KeyGenerator` | Генерация симметричных ключей |
| `KeyPairGenerator` | Генерация пар ключей (RSA, EC) |
| `MessageDigest` | Хеширование (SHA-256, MD5 и др.) |
| `SecretKeyFactory` | Вывод ключей (PBKDF2, SCrypt) |
| `Signature` | Цифровые подписи |
| `Mac` | HMAC операции |
| `KeyGenParameterSpec` | Параметры генерации ключей Keystore |
| `KeyStore` | Анализ хранилища ключей Android Keystore |
| `SSLContext` | Анализ SSL/TLS конфигурации |
| `EncryptedSharedPrefs` | Перехват зашифрованных SharedPreferences |
| `SQLCipher` | Анализ зашифрованных баз данных |

---

## AdBlocker — детали

### Уровни блокировки

| Уровень | Механизм | Что блокирует |
|---------|----------|---------------|
| **SDK** | Хук `loadAd`/`show` на каждом рекламном SDK | Загрузку и показ рекламы |
| **Activity** | Хук `Activity.startActivity` | Запуск рекламных Activity до их создания |
| **WebView** | Хук `WebView.loadUrl` | Рекламные URL (не `file://` — локальные контроллеры SDK) |
| **Network** | Хук `HttpURLConnection.connect` | HTTP-запросы к рекламным серверам |

### Поддерживаемые рекламные SDK

| SDK | Блокировка |
|-----|-----------|
| Google AdMob | AdView, InterstitialAd, RewardedAd, AdListener |
| Facebook Audience Network | AdView, InterstitialAd, RewardedVideoAd |
| Unity Ads | load, show |
| IronSource / LevelPlay | Interstitial, RewardedVideo, Banner |
| AppLovin MAX | MaxInterstitialAd, MaxRewardedAd, MaxAdView, MaxAppOpenAd |
| Vungle | loadAd, playAd |
| Chartboost | Interstitial, RewardedVideo (load, cache, show) |
| Pangle (TikTok) | Interstitial, RewardVideo, Splash |
| StartApp | showAd, Ad.load |
| Yandex Mobile Ads | AdView, InterstitialAd, RewardedAd, AppOpenAd |
| AppNext | Interstitial, Banner, Fullscreen |
| Tapjoy | connect, Offerwall, DirectAction |
| Mintegral (mbridge) | Rewarded, Interstitial, Banner, Splash + legacy |
| Fyber (Digital Turbine) | init, requestAd, Video |
| MyTarget (Mail.ru) | Interstitial, Rewarded, Banner, Native |
| Bigo Ads | Interstitial, Rewarded, Banner, Native, Splash |
| Maticoo | Interstitial, Video, Splash, Banner |
| InMobi | Interstitial, Banner, Native, Rewarded |

### Фильтрация стек-трейсов

`AD_KEYWORDS` -- ключевые слова для фильтрации. Когда `Cipher.init` или другой крипто-метод вызывается из кода рекламного SDK (AdMob, Facebook, Unity и т.д.), стек-трейс автоматически пропускается и не засоряет вывод. Это позволяет сосредоточиться на крипто-операциях самого приложения, а не на шифровании рекламных трекеров. Firebase Remote Config и Firebase Auth **не фильтруются** -- они содержат полезные конфиги приложения.

### Утилита `hasAdKeyword`

Общая функция для проверки строк по списку ключевых слов. Используется для фильтрации стек-трейсов, URL и имён Activity.

---

### Методы bypass

| Метод | Описание |
|-------|----------|
| TrustManager | Подмена TrustManager на доверяющий всё (Android < 7) |
| TrustManagerImpl | Обход `checkTrustedRecursive` и `verifyChain` (Android > 7) |
| OkHttp3 | 4 варианта: `check(String, List)`, `check(String, Certificate)`, `check(String, Certificate[])`, `check$okhttp` |
| Squareup | CertificatePinner (2) + OkHostnameVerifier (2) — OkHttp < v3 |
| Trustkit | OkHostnameVerifier (2) + PinningTrustManager |
| OpenSSLSocketImpl | Conscrypt (2) + Apache Harmony |
| OpenSSLEngineSocketImpl | Conscrypt engine |
| CertPinManager | Conscrypt (2) + CWAC-Netsecurity |
| Appcelerator | PinningTrustManager |
| Fabric | PinningTrustManager |
| PhoneGap | sslCertificateChecker |
| IBM MobileFirst | pinTrustedCertificatePublicKey (2) |
| IBM WorkLight | HostNameVerifierWithCertificatePinning (4) + Androidgap |
| Netty | FingerprintTrustManagerFactory |
| Chromium Cronet | enablePublicKeyPinningBypass + addPublicKeyPins |
| Flutter | HttpCertificatePinning + SslPinningPlugin |
| Boye / Apache | AbstractVerifier |
| WebViewClient | onReceivedSslError (2) + onReceivedError (2) |
| React Native | RNCWebViewClient onReceivedSslError + onReceivedError |
| Cordova | WebViewClient onReceivedSslError |
| Dynamic Patcher | Автопатч SSLPeerUnverifiedException для неизвестных методов |

---

## Что добавлено

### Крипто-модули

- **SecretKeySpec** — прямой перехват создания ключей
- **IvParameterSpec** — прямой перехват IV
- **KeyStore** — анализ `getEntry`, `getKey`, `setEntry`, `load`
- **MessageDigest** — хеширование (SHA-256, MD5)
- **Mac** — HMAC операции
- **Signature** — цифровые подписи
- **KeyGenerator / KeyPairGenerator** — генерация ключей
- **SecretKeyFactory** — вывод ключей (PBKDF2, SCrypt)
- **Tink** — Google Tink крипто-библиотека

### Безопасность

- **SSLContext** — анализ SSL/TLS конфигурации
- **SSLUnpinner** — обход SSL пиннинга (27 методов bypass)

### Хранение данных

- **EncryptedSharedPrefs** — перехват зашифрованных SharedPreferences
- **SQLCipher** — анализ зашифрованных баз данных

### Удобство

- **AdBlocker** — блокировка рекламы с 5 уровнями защиты
- **PRINT_STACKTRACE** — переключатель вывода стека вызовов
- **AD_KEYWORDS** — фильтрация рекламных/аналитических SDK
- **Счётчик вызовов (#N)** — показывает сколько раз вызван каждый метод
- **HEX вывод** — автоматическое отображение HEX для ключей 16/20/24/32 байта
- **Модульность** — включение/выключение отдельных модулей

---

## Пример вывода

### Шифрование AES/CBC

```
[Cipher.init] #1
  transformation: AES/CBC/PKCS5Padding
  mode: ENCRYPT
  key: oOej3ieYR1DYWnubZmjIXg==
  keyHEX: a0e7ebde878758d750d6d6ae66668586
  iv: odaCWSCFyF7C+9xclJdIDw==

[Cipher.doFinal] #1
  input: This is Secret
  output: uU0F7JMrbFUGoYoXBCOLiQ==
```

### С бэктрейсом

```
[Cipher.init] #1
  transformation: AES/GCM/NoPadding
  mode: ENCRYPT
  key: oHeY9IH3/QHKXVu3BCTbWQ==
  iv: +koINuprs1G9C4ir
  tagLength: 128
Backtrace (depth: 19)
1. com.android.internal.os.ZygoteInit.main(ZygoteInit.java:861)
  2. ...
    16. com.example.app.MainActivity.onCreate(MainActivity.kt:20)
      17. javax.crypto.Cipher.init(Cipher.java:-2)
[End of Backtrace]
```

### KeyStore анализ

```
[KeyStore.getInstance] #1
  type: BKS

[KeyStore.load] #1
  password: mypassword

[KeyStore.getEntry] #1
  alias: mykey
  resultType: java.security.KeyStore$PrivateCertEntry
```

---

## Лицензия

MIT License

---

## Автор

**Mehdi Karzari** (оригинальный скрипт)
- GitHub: [https://github.com/QM4RS](https://github.com/QM4RS)
- Telegram: [@QM4RS](https://t.me/QM4RS)
