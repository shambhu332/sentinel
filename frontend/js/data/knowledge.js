// SENTINEL RAG knowledge base — 61-passage corpus mirror.
// Auto-generated from sentinel/rag/data/*.json.

export const PASSAGES = [
  {
    "source": "MASVS",
    "control_id": "MSTG-AUTH-1",
    "title": "Server-side authentication of users",
    "category": "auth",
    "text": "If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint. Authentication must always be performed server-side; the mobile client must never trust client-side flags claiming a user is authenticated."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-AUTH-2",
    "title": "Stateful session identifiers must be invalidated server-side on logout",
    "category": "auth",
    "text": "If stateful session management is used, the remote endpoint terminates existing sessions when the user logs out and rotates the session identifier. Tokens carried in URL query parameters violate this control because URLs are persisted in logs and Referer headers."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-AUTH-3",
    "title": "Re-authentication for sensitive operations",
    "category": "auth",
    "text": "The remote endpoint requires the user to authenticate or re-authenticate for accessing data or operations of high sensitivity. Session id / token must be refreshed on every authentication transition; client-supplied identifiers must never become the authoritative session."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-AUTH-7",
    "title": "Sessions are invalidated at remote endpoint after timeout",
    "category": "auth",
    "text": "Sessions are invalidated at the remote endpoint after a predefined period of inactivity, and access tokens have a clearly bounded lifetime. Logout flows on the client must remove every persisted credential, including refresh tokens, from SharedPreferences and equivalent stores."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-AUTH-8",
    "title": "Biometric authentication is bound to cryptographic operations",
    "category": "auth",
    "text": "Biometric authentication is not event-bound (i.e. using only a true/false return). It is invoked with a CryptoObject so the biometric prompt unlocks a cryptographic primitive, defeating Frida-based bypass of the success callback."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-NETWORK-1",
    "title": "Data is encrypted on the network using TLS",
    "category": "network",
    "text": "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app, no cleartext fallback. WebSocket (ws://), DNS-over-cleartext, and FCM token uploads over HTTP all violate this control."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-NETWORK-2",
    "title": "TLS settings follow current best practices",
    "category": "network",
    "text": "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards. Custom X509TrustManager / HostnameVerifier that accept all certificates is a critical violation."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-NETWORK-3",
    "title": "Verifies the X.509 certificate of the remote endpoint",
    "category": "network",
    "text": "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted. Empty checkServerTrusted implementations and HostnameVerifier returning true unconditionally defeat this control."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-NETWORK-4",
    "title": "Certificate pinning",
    "category": "network",
    "text": "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-PLATFORM-1",
    "title": "IPC mechanisms are properly secured",
    "category": "platform",
    "text": "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected. Exported BroadcastReceivers, Services, and Activities require explicit android:permission with signature-level protection, or intent.setPackage to restrict delivery."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-PLATFORM-2",
    "title": "Limits the access permissions of FileProvider entries",
    "category": "platform",
    "text": "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected. FileProvider declarations must always be android:exported=\"false\" and rely on per-URI grant flags."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-PLATFORM-3",
    "title": "Deep links are verified",
    "category": "platform",
    "text": "The app does not export sensitive functionality via deep links unless these are properly protected. App Links must use android:autoVerify=\"true\" with /.well-known/assetlinks.json hosted on the domain. Custom schemes need explicit host filters to prevent same-scheme hijack."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-PLATFORM-9",
    "title": "Activities prevent overlay-based tap-jacking",
    "category": "platform",
    "text": "Activities that handle sensitive operations (login, payment, biometric, password reset) set android:filterTouchesWhenObscured=\"true\" or call setFilterTouchesWhenObscured(true) on touch-receiving views so MotionEvents with FLAG_WINDOW_IS_OBSCURED are dropped."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-STORAGE-1",
    "title": "System credential storage facilities used appropriately",
    "category": "storage",
    "text": "System credential storage facilities are used appropriately to store sensitive data, such as personally identifiable information (PII), credentials and keys. Plaintext passwords in .txt/.json/.properties files violate this control."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-STORAGE-2",
    "title": "No sensitive data stored outside app container",
    "category": "storage",
    "text": "No sensitive data is stored outside of the app container or system credential storage facilities. Writes to getExternalStorageDirectory / DIRECTORY_DOWNLOADS / /sdcard are world-readable on API \u2264 28 and persist across uninstall."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-STORAGE-3",
    "title": "No sensitive data written to application logs",
    "category": "storage",
    "text": "No sensitive data is written to application logs. Log.d/v/i/w/e calls carrying FCM tokens, OAuth refresh tokens, OkHttp body / header logging at release time, or PII land in logcat and are scrapeable by any process with READ_LOGS."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-STORAGE-8",
    "title": "No sensitive data included in backups",
    "category": "storage",
    "text": "No sensitive data is included in backups generated by the mobile operating system. Auto-backup rules with wildcard <include> elements or domain=\"root\" ship secrets to Google Drive. Always exclude credential files explicitly or set android:allowBackup=\"false\"."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-STORAGE-14",
    "title": "Sensitive data stored on memory at rest is encrypted",
    "category": "storage",
    "text": "If sensitive data is still required to be stored locally, the data should be encrypted using a key derived from hardware-backed storage. Prefer EncryptedSharedPreferences or seal data with an Android Keystore key."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-CRYPTO-1",
    "title": "App does not rely on symmetric cryptography with hardcoded keys",
    "category": "crypto",
    "text": "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption. Hardcoded AES/RSA keys, BuildConfig constants, static final String passphrases for SQLCipher, and Base64-encoded keys in source all violate this control."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-CRYPTO-2",
    "title": "App uses proven implementations of cryptographic primitives",
    "category": "crypto",
    "text": "The app uses proven implementations of cryptographic primitives. ECB mode, AES/GCM with deterministic nonces, AES/CBC with predictable IVs, and DES/RC4/MD5/SHA1 all violate this control."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-CRYPTO-6",
    "title": "All random values are generated using a cryptographically secure RNG",
    "category": "crypto",
    "text": "All random values are generated using a sufficiently secure random number generator. SecureRandom seeded with System.currentTimeMillis(), java.util.Random for token generation, and string-literal getBytes() seeds all collapse the output to a predictable sequence."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-CODE-2",
    "title": "App has been built in release mode",
    "category": "code",
    "text": "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable). android:debuggable=\"true\" in a shipping APK lets any local process run-as the UID and read the private data directory."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-CODE-8",
    "title": "Deserialization, if any, is performed safely",
    "category": "code",
    "text": "Deserialization, if any, is performed safely. ObjectInputStream.readObject fed from a network / Intent / external-storage source is an arbitrary-code-execution primitive via gadget chains. Prefer JSON or Protocol Buffers."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-RESILIENCE-2",
    "title": "App detects whether it is being debugged",
    "category": "resilience",
    "text": "The app detects whether it is being debugged. WebView.setWebContentsDebuggingEnabled(true) and HttpLoggingInterceptor.Level.BODY shipped to release builds give attackers a fully-instrumented session via adb."
  },
  {
    "source": "MASVS",
    "control_id": "MSTG-RESILIENCE-3",
    "title": "App detects the presence of root or jailbreak",
    "category": "resilience",
    "text": "The app detects whether it is being executed on a rooted or jailbroken device. The app's response is to alert the user, deny continued operation, or both, depending on the data sensitivity and business policy."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M1",
    "title": "Improper Credential Usage",
    "category": "owasp",
    "text": "Improper credential usage encompasses hardcoded credentials, insecure credential storage in plain SharedPreferences / files, transmission over insecure channels, and credentials persisted past logout. Mobile apps must derive credentials at runtime, store them in hardware-backed keystores, and rotate them on every authentication transition."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M2",
    "title": "Inadequate Supply Chain Security",
    "category": "owasp",
    "text": "Vulnerabilities in third-party libraries (Log4j-style RCE, vulnerable OkHttp / Bouncy Castle), build-time secret leakage into APK resources, and unsigned in-app updates all fall under M2. Mitigations include SCA scanning, dependency pinning, in-house code signing on every update bundle, and an approved-libraries allowlist."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M3",
    "title": "Insecure Authentication / Authorization",
    "category": "owasp",
    "text": "Client-side-only authentication checks, missing server-side authorization on REST IDs, OAuth redirect_uri without strict validation, and session fixation via deep-link tokens. The mobile client must treat itself as untrusted; the server is the authority on every access decision."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M4",
    "title": "Insufficient Input/Output Validation",
    "category": "owasp",
    "text": "Inputs from Intents, deep links, WebView JS bridges, and IPC must be validated as strictly as inputs from the network. Outputs to logs, files, and broadcasts must be sanitized. Intent-redirect (CWE-926), receiver-chain hijack, and mutable-PendingIntent vulnerabilities all stem from missing validation."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M5",
    "title": "Insecure Communication",
    "category": "owasp",
    "text": "Cleartext HTTP, weak TLS configurations (custom TrustManager / HostnameVerifier), missing certificate pinning, DNS-over-cleartext opt-outs, WebSocket over ws://, and WebView remote-debugging in release builds. Apps must enforce TLS with proper validation and honor the user's Private DNS preference."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M6",
    "title": "Inadequate Privacy Controls",
    "category": "owasp",
    "text": "Excessive permissions (READ_SMS, BIND_ACCESSIBILITY_SERVICE without justification), PII leakage via logs or auto-backup, GDPR/CCPA non-compliance, and FCM tokens shipped over HTTP. Apps must request least privilege, surface a privacy policy, and redact sensitive fields from telemetry."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M7",
    "title": "Insufficient Binary Protections",
    "category": "owasp",
    "text": "Missing anti-tamper, missing root detection, unobfuscated bytecode, exported JNI symbols revealing internals, and ungated System.loadLibrary calls. Apps handling financial / health data should apply RASP, obfuscation, and integrity checks on every release build."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M8",
    "title": "Security Misconfiguration",
    "category": "owasp",
    "text": "Debuggable=\"true\" in release manifests, FileProvider entries with wildcard paths, exported components without permission gating, and verbose error messages exposing stack traces. Misconfiguration is the single most common high-severity finding in shipped Android apps."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M9",
    "title": "Insecure Data Storage",
    "category": "owasp",
    "text": "Plaintext SharedPreferences for tokens, world-readable external storage writes, SQLCipher with hardcoded passphrases, and credential files written to Downloads. Mobile devices are shared, lost, and stolen; persisted secrets must be encrypted with hardware-backed keys."
  },
  {
    "source": "OWASP_MOBILE",
    "control_id": "M10",
    "title": "Insufficient Cryptography",
    "category": "owasp",
    "text": "Weak algorithms (DES, RC4, MD5, SHA-1), insufficient key length (RSA-1024), ECB mode, predictable IVs in CBC, deterministic GCM nonces, and PRNGs seeded with clock values. Cryptography is rarely broken by attacks on the primitive; it's broken by implementation choices."
  },
  {
    "source": "CWE",
    "control_id": "CWE-22",
    "title": "Path Traversal",
    "category": "weakness",
    "text": "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname."
  },
  {
    "source": "CWE",
    "control_id": "CWE-79",
    "title": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "category": "weakness",
    "text": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page. In mobile this manifests in WebView JS interfaces and dangerouslySetInnerHTML in React Native."
  },
  {
    "source": "CWE",
    "control_id": "CWE-89",
    "title": "SQL Injection",
    "category": "weakness",
    "text": "The product constructs all or part of an SQL command using externally-influenced input but does not neutralize or incorrectly neutralizes special elements. ContentProvider rawQuery with caller-supplied selection arguments is the canonical Android instance."
  },
  {
    "source": "CWE",
    "control_id": "CWE-200",
    "title": "Exposure of Sensitive Information",
    "category": "weakness",
    "text": "The product exposes sensitive information to an actor that is not explicitly authorized to have access. Tokens in URL query strings, FCM tokens logged to logcat, and unprotected broadcasts all fall under CWE-200."
  },
  {
    "source": "CWE",
    "control_id": "CWE-209",
    "title": "Generation of Error Message Containing Sensitive Information",
    "category": "weakness",
    "text": "The product generates an error message that includes sensitive information about its environment, users, or associated data. Stack traces in user-facing dialogs and BuildConfig.DEBUG branches that survive R8 are mobile-specific cases."
  },
  {
    "source": "CWE",
    "control_id": "CWE-256",
    "title": "Plaintext Storage of a Password",
    "category": "weakness",
    "text": "Storing a password in plaintext may result in a system compromise. SharedPreferences without encryption, credentials.json files, and \"remember me\" features that persist the user's password instead of a refresh token are direct violations."
  },
  {
    "source": "CWE",
    "control_id": "CWE-295",
    "title": "Improper Certificate Validation",
    "category": "weakness",
    "text": "The product does not validate, or incorrectly validates, a certificate. Custom X509TrustManager implementations with empty checkServerTrusted bodies and HostnameVerifier returning true unconditionally are CWE-295 instances."
  },
  {
    "source": "CWE",
    "control_id": "CWE-311",
    "title": "Missing Encryption of Sensitive Data",
    "category": "weakness",
    "text": "The product does not encrypt sensitive or critical information before storage or transmission. WebSocket over ws://, FCM token uploads to HTTP collectors, and unencrypted database files all violate CWE-311."
  },
  {
    "source": "CWE",
    "control_id": "CWE-319",
    "title": "Cleartext Transmission of Sensitive Information",
    "category": "weakness",
    "text": "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors. http:// URLs in network requests and TLS opt-outs in NetworkSecurityConfig fall under CWE-319."
  },
  {
    "source": "CWE",
    "control_id": "CWE-326",
    "title": "Inadequate Encryption Strength",
    "category": "weakness",
    "text": "The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. AES-128 with insecure key derivation, RSA-1024, and DES are the common mobile cases."
  },
  {
    "source": "CWE",
    "control_id": "CWE-327",
    "title": "Use of a Broken or Risky Cryptographic Algorithm",
    "category": "weakness",
    "text": "The product uses a broken or risky cryptographic algorithm or protocol. DES, RC4, MD5, SHA-1, and ECB mode are all broken; AES-GCM with reused nonces is risky despite the algorithm being sound."
  },
  {
    "source": "CWE",
    "control_id": "CWE-328",
    "title": "Use of Weak Hash",
    "category": "weakness",
    "text": "The product uses an algorithm that produces a digest (output value) that does not meet security expectations for a hash function that allows an adversary to find collisions or pre-images. MD5 collisions are trivial; SHA-1 is broken since 2017."
  },
  {
    "source": "CWE",
    "control_id": "CWE-330",
    "title": "Use of Insufficiently Random Values",
    "category": "weakness",
    "text": "The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers. java.util.Random for token generation, SecureRandom seeded with System.currentTimeMillis, and PRNG state leaks all qualify."
  },
  {
    "source": "CWE",
    "control_id": "CWE-331",
    "title": "Insufficient Entropy",
    "category": "weakness",
    "text": "The product uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others. Common in IV / nonce generation."
  },
  {
    "source": "CWE",
    "control_id": "CWE-345",
    "title": "Insufficient Verification of Data Authenticity",
    "category": "weakness",
    "text": "The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data. In-app updaters that install APKs without verifying the signing certificate or a pinned SHA-256 digest are textbook cases."
  },
  {
    "source": "CWE",
    "control_id": "CWE-352",
    "title": "Cross-Site Request Forgery (CSRF)",
    "category": "weakness",
    "text": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request. Mobile-side: deep-link CSRF via Intent and WebView postMessage."
  },
  {
    "source": "CWE",
    "control_id": "CWE-359",
    "title": "Exposure of Private Personal Information to an Unauthorized Actor",
    "category": "weakness",
    "text": "The product does not properly prevent a person's private, personal information from being accessed by actors who either are not explicitly authorized to access the information or do not have the implicit consent of the person about whom the information is collected."
  },
  {
    "source": "CWE",
    "control_id": "CWE-384",
    "title": "Session Fixation",
    "category": "weakness",
    "text": "Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions. Deep-link-supplied session_id values persisted into the auth-token slot are mobile instances."
  },
  {
    "source": "CWE",
    "control_id": "CWE-470",
    "title": "Use of Externally-Controlled Input to Select Classes or Code",
    "category": "weakness",
    "text": "The product uses external input with reflection to select which classes or code to use. System.loadLibrary / System.load with an Intent-extra-derived argument is the canonical Android case."
  },
  {
    "source": "CWE",
    "control_id": "CWE-502",
    "title": "Deserialization of Untrusted Data",
    "category": "weakness",
    "text": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid. Java native ObjectInputStream.readObject fed from network / Intent / external storage yields RCE via gadget chains."
  },
  {
    "source": "CWE",
    "control_id": "CWE-532",
    "title": "Insertion of Sensitive Information into Log File",
    "category": "weakness",
    "text": "Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information. Log.d(...) of FCM tokens, OAuth refresh tokens, and OkHttp body logging at release time all qualify."
  },
  {
    "source": "CWE",
    "control_id": "CWE-639",
    "title": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "category": "weakness",
    "text": "The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data. REST endpoints accepting /users/{id} without ownership checks are the standard case."
  },
  {
    "source": "CWE",
    "control_id": "CWE-749",
    "title": "Exposed Dangerous Method or Function",
    "category": "weakness",
    "text": "The product provides an Applet, ActiveX control, or other component that contains a method or function that, when called, can lead to security risk. addJavascriptInterface and @JavascriptInterface bridges expose Java methods to attacker-controlled JS."
  },
  {
    "source": "CWE",
    "control_id": "CWE-798",
    "title": "Use of Hardcoded Credentials",
    "category": "weakness",
    "text": "The product contains hardcoded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."
  },
  {
    "source": "CWE",
    "control_id": "CWE-926",
    "title": "Improper Export of Android Application Components",
    "category": "weakness",
    "text": "The Android application exports a component for use by other applications, but does not properly restrict which applications can launch the component or access the data it contains. Intent-redirect (confused-deputy) and unprotected broadcast both fall under CWE-926."
  },
  {
    "source": "CWE",
    "control_id": "CWE-927",
    "title": "Use of Implicit Intent for Sensitive Communication",
    "category": "weakness",
    "text": "The Android application uses an implicit intent for transmitting sensitive data to other applications. Implicit broadcasts of auth state, OTPs, or payment events are eavesdroppable by any app on the device that registers the action."
  }
];

export const PASSAGE_TOTAL = PASSAGES.length;
export const PASSAGE_SOURCES = [...new Set(PASSAGES.map(p => p.source))];
