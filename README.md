# 🔍 frida-java-reverse

Мощный [Frida](https://frida.re) скрипт для реверс-инжиниринга Android-приложений. Перехватывает крипто-операции, анализирует безопасность и блокирует рекламу.

---

## 🙏 Благодарности

Этот скрипт основан на оригинальном проекте **frida-java-crypto-spy**:

- **Автор оригинала**: [Mehdi Karzari](https://github.com/QM4RS/frida-java-crypto-spy)
- **Telegram**: [@QM4RS](https://t.me/QM4RS)
- **GitHub**: [https://github.com/QM4RS/frida-java-crypto-spy](https://github.com/QM4RS/frida-java-crypto-spy)

Оригинальный скрипт предоставлял базовый перехват `javax.crypto.Cipher` с логированием ключей, IV и данных.

---

## 🚀 Быстрый старт

```bash
frida -U -f target.app.package -l frida-java-reverse.js
```

---

## ⚙️ Конфигурация

В начале файла `frida-java-reverse.js` находятся настройки:

```javascript
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
    KeyStore: true,
    SSLContext: false,
    OkHttp: false,
    EncryptedSharedPrefs: false,
    SQLCipher: false,
    Tink: true,
    AdBlocker: false
};

const IGNORE_KEYWORDS = [ /* ... */ ];
const PRINT_STACKTRACE = true;
```

---

## 📦 Модули

### Включены по умолчанию

| Модуль | Описание |
|--------|----------|
| `Cipher` | Перехват шифрования/дешифрования (AES, DES, RSA и др.) |
| `SecretKeySpec` | Прямой перехват создания ключей |
| `IvParameterSpec` | Перехват вектора инициализации |
| `KeyStore` | Анализ хранилища ключей Android Keystore |
| `Tink` | Перехват Google Tink крипто-библиотеки |

### Выключены по умолчанию (включаются при необходимости)

| Модуль | Описание |
|--------|----------|
| `KeyGenerator` | Генерация симметричных ключей |
| `KeyPairGenerator` | Генерация пар ключей (RSA, EC) |
| `MessageDigest` | Хеширование (SHA-256, MD5 и др.) |
| `SecretKeyFactory` | Вывод ключей (PBKDF2, SCrypt) |
| `Signature` | Цифровые подписи |
| `Mac` | HMAC операции |
| `KeyGenParameterSpec` | Параметры генерации ключей Keystore |
| `SSLContext` | Анализ SSL/TLS конфигурации |
| `OkHttp` | Обнаружение пиннинга сертификатов |
| `EncryptedSharedPrefs` | Перехват зашифрованных SharedPreferences |
| `SQLCipher` | Анализ зашифрованных баз данных |
| `AdBlocker` | Блокировка рекламы и спуфинг callback'ов |

---

## 🛡️ Возможности оригинального скрипта

Оригальный [frida-java-crypto-spy](https://github.com/QM4RS/frida-java-crypto-spy) предоставлял:

- Перехват `Cipher.init`, `update`, `doFinal`
- Логирование алгоритма, режима, ключа и IV
- Поддержку AES/CBC, AES/GCM и других режимов
- Базовый вывод в Base64/UTF-8

---

## 🔧 Что добавлено в新 версии

### Крипто-модули

- **SecretKeySpec** — прямой перехват создания ключей (не только через Cipher.init)
- **IvParameterSpec** — прямой перехват IV
- **KeyStore** — анализ `getEntry`, `getKey`, `setEntry`, `load` в Android Keystore
- **MessageDigest** — хеширование (SHA-256, MD5)
- **Mac** — HMAC операции
- **Signature** — цифровые подписи
- **KeyGenerator / KeyPairGenerator** — генерация ключей
- **SecretKeyFactory** — вывод ключей (PBKDF2, SCrypt)
- **Tink** — Google Tink крипто-библиотека

### Безопасность

- **SSLContext** — анализ SSL/TLS конфигурации
- **OkHttp CertificatePinner** — обнаружение пиннинга сертификатов
- **TrustManagerImpl** — перехват цепочки доверия

### Хранение данных

- **EncryptedSharedPrefs** — перехват зашифрованных SharedPreferences
- **SQLCipher** — анализ зашифрованных баз данных

### Удобство

- **AdBlocker** — блокировка рекламы (AdMob, Facebook, Unity, IronSource и др.)
- **PRINT_STACKTRACE** — переключатель вывода стека вызовов
- **IGNORE_KEYWORDS** — фильтрация рекламных/аналитических SDK
- **Счётчик вызовов (#N)** — показывает сколько раз вызван каждый метод
- **HEX вывод** — автоматическое отображение HEX для ключей 16/20/24/32 байта
- **Модульность** — включение/выключение отдельных модулей

---

## 📄 Пример вывода

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
📚 Backtrace (depth: 19) ↓↓↓
1. com.android.internal.os.ZygoteInit.main(ZygoteInit.java:861)
  2. ...
    16. com.example.app.MainActivity.onCreate(MainActivity.kt:20)
      17. javax.crypto.Cipher.init(Cipher.java:-2)
📚 [End of Backtrace]
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

## 📋 Список фильтрации рекламы

Игнорируются при анализе стека вызовов:

- Google AdMob, Analytics
- Facebook Ads
- Yandex AppMetrica, Ads
- Unity Ads
- IronSource, AppLovin, Vungle
- Chartboost, Mbridge, InMobi
- Pangle (TikTok)
- Firebase Analytics, Messaging, Crashlytics
- AppsFlyer, Adjust, Branch
- Amplitude, Mixpanel, Segment
- и другие рекламные/аналитические SDK

---

## 📝 Лицензия

MIT License

---

## 👤 Автор

**Mehdi Karzari** (оригинальный скрипт)
- GitHub: [https://github.com/QM4RS](https://github.com/QM4RS)
- Telegram: [@QM4RS](https://t.me/QM4RS)
