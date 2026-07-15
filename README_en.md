# frida-java-reverse

A powerful [Frida](https://frida.re) script for Android reverse engineering. Intercepts crypto operations, analyzes security, bypasses SSL pinning, and blocks ads.

---

## Credits

Based on the original **frida-java-crypto-spy** project:

- **Original author**: [Mehdi Karzari](https://github.com/QM4RS/frida-java-crypto-spy)
- **Telegram**: [@QM4RS](https://t.me/QM4RS)
- **GitHub**: [https://github.com/QM4RS/frida-java-crypto-spy](https://github.com/QM4RS/frida-java-crypto-spy)

The original script provided basic `javax.crypto.Cipher` interception with key, IV, and data logging.

SSL Unpinner based on https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/ by Maurizio Siddu.

---

## Quick Start

```bash
frida -U -f target.app.package -l frida-java-reverse.js
```

---

## Configuration

Settings are at the top of `frida-java-reverse.js`:

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
    SSLUnpinner: true,          // SSL pinning bypass (OkHttp, Conscrypt, WebView, Flutter, etc.)
    EncryptedSharedPrefs: false,// androidx.security.crypto
    SQLCipher: false,           // net.sqlcipher
    Tink: true,                 // com.google.crypto.tink
    AdBlocker: true             // Ad blocking + ad noise suppression in crypto logs
};
```

---

## PRINT_STACKTRACE

Global toggle at the top of the file. When `true`, each intercepted call includes a backtrace showing the call depth and path — from the Java method back to the app's entry point. When `false`, only call data (key, IV, payload) is printed without the stack.

---

## Modules

### Enabled by default

| Module | Description |
|--------|-------------|
| `Cipher` | Intercept encryption/decryption (AES, DES, RSA, etc.) |
| `SecretKeySpec` | Direct interception of key creation |
| `IvParameterSpec` | Intercept initialization vectors |
| `Tink` | Intercept Google Tink crypto library |
| `SSLUnpinner` | Bypass SSL certificate pinning (27 methods) |
| `AdBlocker` | Block ads + fake `onAdDismissed` callback + suppress ad SDK noise in crypto logs |

### Disabled by default

| Module | Description |
|--------|-------------|
| `KeyGenerator` | Symmetric key generation |
| `KeyPairGenerator` | Key pair generation (RSA, EC) |
| `MessageDigest` | Hashing (SHA-256, MD5, etc.) |
| `SecretKeyFactory` | Key derivation (PBKDF2, SCrypt) |
| `Signature` | Digital signatures |
| `Mac` | HMAC operations |
| `KeyGenParameterSpec` | Keystore key generation parameters |
| `KeyStore` | Android Keystore key storage analysis |
| `SSLContext` | SSL/TLS configuration analysis |
| `EncryptedSharedPrefs` | Intercept encrypted SharedPreferences |
| `SQLCipher` | Analyze encrypted SQLite databases |

---

## AdBlocker -- details

### Blocking levels

| Level | Mechanism | What it blocks |
|-------|-----------|----------------|
| **SDK** | Hook `loadAd`/`show` on each ad SDK | Ad loading and display |
| **Activity** | Hook `Activity.startActivity` | Ad Activity launch before creation |
| **WebView** | Hook `WebView.loadUrl` | Ad URLs (not `file://` -- local SDK controllers) |
| **Network** | Hook `HttpURLConnection.connect` | HTTP requests to ad servers |

### Supported ad SDKs

| SDK | Blocking |
|-----|----------|
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

### Stack trace filtering

`AD_KEYWORDS` contains keywords for filtering. When `Cipher.init` or other crypto methods are called from ad SDK code (AdMob, Facebook, Unity, etc.), the stack trace is automatically skipped to keep logs clean. This allows focusing on the app's own crypto operations instead of ad tracker encryption. Firebase Remote Config and Firebase Auth are **not filtered** -- they contain useful app configs.

### `hasAdKeyword` utility

Shared function for checking strings against keyword lists. Used for filtering stack traces, URLs, and Activity names.

### Fake `onAdDismissed` callback

Some apps (VPN clients, streaming services) show interstitial/rewarded ads before functionality and **wait for the `onAdDismissed` callback** before proceeding. Simply blocking the Activity prevents the callback from firing — the app hangs indefinitely.

AdBlocker intercepts ad SDK listener setters (`setEventListener`, `setFullScreenContentCallback`, `setAdListener`) for Yandex, Google AdMob, and Facebook. When an ad Activity is blocked, it automatically fires `onAdDismissed` / `onAdDismissedFullScreenContent` — the app thinks the ad was shown and dismissed, and continues normally.

---

### Bypass methods

| Method | Description |
|--------|-------------|
| TrustManager | Replace TrustManager with one that trusts all (Android < 7) |
| TrustManagerImpl | Bypass `checkTrustedRecursive` and `verifyChain` (Android > 7) |
| OkHttp3 | 4 variants: `check(String, List)`, `check(String, Certificate)`, `check(String, Certificate[])`, `check$okhttp` |
| Squareup | CertificatePinner (2) + OkHostnameVerifier (2) -- OkHttp < v3 |
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
| Dynamic Patcher | Auto-patch SSLPeerUnverifiedException for unknown methods |

---

## What's added

### Crypto modules

- **SecretKeySpec** -- direct interception of key creation
- **IvParameterSpec** -- direct IV interception
- **KeyStore** -- analyze `getEntry`, `getKey`, `setEntry`, `load`
- **MessageDigest** -- hashing (SHA-256, MD5)
- **Mac** -- HMAC operations
- **Signature** -- digital signatures
- **KeyGenerator / KeyPairGenerator** -- key generation
- **SecretKeyFactory** -- key derivation (PBKDF2, SCrypt)
- **Tink** -- Google Tink crypto library

### Security

- **SSLContext** -- SSL/TLS configuration analysis
- **SSLUnpinner** -- SSL pinning bypass (27 methods)

### Data storage

- **EncryptedSharedPrefs** -- intercept encrypted SharedPreferences
- **SQLCipher** -- analyze encrypted SQLite databases

### Convenience

- **AdBlocker** -- 5-level ad blocking + fake `onAdDismissed` callback for apps that wait for ad dismissal
- **PRINT_STACKTRACE** -- toggle stack trace output
- **AD_KEYWORDS** -- filter ad/analytics SDK noise from crypto operations
- **Call counter (#N)** -- shows how many times each method was called
- **HEX output** -- auto-display HEX for 16/20/24/32-byte keys
- **Modularity** -- enable/disable individual modules

---

## Output examples

### AES/CBC encryption

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

### With backtrace

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

### KeyStore analysis

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

## License

MIT License

---

## Author

**Mehdi Karzari** (original script)
- GitHub: [https://github.com/QM4RS](https://github.com/QM4RS)
- Telegram: [@QM4RS](https://t.me/QM4RS)
