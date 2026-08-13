# macOS native アプリからの passkey PRF 利用可能性

- Date: 2026-08-14

## 判明した事実

- macOS native アプリは AuthenticationServices の platform public-key credential API から WebAuthn PRF 拡張を利用できる。ローカルの Xcode macOS SDK header では、registration/assertion request と結果の `prf` property、および PRF 入出力型がすべて `API_AVAILABLE(macos(15.0), ios(18.0), visionos(2.0))` と宣言されている。
- assertion の主な Objective-C API は `ASAuthorizationPublicKeyCredentialPRFAssertionInputValues`、`ASAuthorizationPublicKeyCredentialPRFAssertionInput`、`ASAuthorizationPublicKeyCredentialPRFAssertionOutput` である。salt は `saltInput1` と任意の `saltInput2`、結果は `first` と任意の `second`。既定入力に加え credential ID (`NSData`) ごとの `perCredentialInputValues` を指定できる。
- registration では `ASAuthorizationPublicKeyCredentialPRFRegistrationInput.checkForSupport` と結果の `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput.isSupported` により、その credential が PRF を使えるか確認できる。registration 時に入力 salt を渡して `first` / `second` を得る経路もある。
- security key credential の native PRF property は、確認した SDK では platform passkey より遅い `API_AVAILABLE(macos(26.4), ios(26.4))` である。本調査の macOS 15 以降という結論は platform passkey に対するもの。
- PRF と `largeBlob` は別機能である。PRF は credential 内部の秘密と呼出側の salt から固定長の疑似乱数値を評価し、credential の秘密そのものを公開しない。`largeBlob` は credential に関連付けた可変データを read/write する保存機能で、macOS 14.0 からの API である。vault master key の導出には PRF、暗号文や小規模メタデータの保存には `largeBlob` という責務差がある。
- WebAuthn Level 3 の PRF は authenticator の credential 固有秘密を用いる疑似乱数関数であるため、同一 credential secret と同一入力に対する評価値は決定的である。ただし RP が渡した salt は client 側で RP ID と `prf` label を含めてハッシュされてから authenticator の `hmac-secret` に渡るため、「生 salt だけ」が出力を決めるわけではない。
- AuthenticationServices の PRF は assertion フローの一部であり、PRF 評価だけを無 UI の background API として呼ぶ経路ではない。assertion request の `userVerificationPreference` で `required` / `preferred` / `discouraged` を要求できるが、最終的な UI、credential 選択、認証方法は OS・authenticator・credential 状態に依存する。毎回 Touch ID が必ず出る、または `discouraged` なら UI が出ない、という保証は公開 API からは確認できない。
- synced passkey は credential material を end-to-end encrypted な同期機構で別デバイスへ持ち運ぶ multi-device credential である。一方、Apple 公開資料に「iCloud Keychain の PRF 出力がデバイス間で byte-for-byte 同一」と明記した文言は本調査では確認できず、Apple 実機マトリクスも未確認である。
- Secure Enclave 対抗案は、`kSecAttrTokenIDSecureEnclave` で生成した非 exportable EC private keyに `SecAccessControl` の `.privateKeyUsage` と `.biometryCurrentSet` または `.biometryAny` を付け、ランダムな vault key を公開鍵暗号または key agreement + KDF で wrap/unwrap する構成になる。Secure Enclave key は端末外へ export・同期できないため可搬性はないが、端末束縛と biometric policy の意味は PRF より明確で API も成熟している。
- Rust では AuthenticationServices の PRF 型に対する完成済み high-level crate は確認できなかった。`objc2` / `objc2-foundation` を使う直接 Objective-C FFI、または必要な宣言を bindings に追加する経路が現実的である。Secure Enclave は `security-framework` / `security-framework-sys` から Security.framework を使えるが、`SecAccessControlCreateWithFlags`、定数、`LAContext` 組込みの全てが安全な high-level API に揃っているとは限らず、raw FFI と `objc2-local-authentication` の併用を見込むべきである。

## 実用的な示唆 / ベストプラクティス

現時点の cache-warden の既定案には **Secure Enclave key + `biometryCurrentSet` ACL でランダム vault key を wrap する構成を推奨する**。

理由は、cache-warden が macOS daemon であり、vault の端末間可搬性よりも、端末束縛、明示的な biometric policy、成熟した Security.framework、認証 UI の発火点を unwrap 操作に局所化できることの価値が高いからである。`biometryCurrentSet` は biometric 登録集合が変わると key を使えなくするため、復旧用の再初期化・recovery 設計が必須になる。登録変更後も継続利用を優先する場合だけ `biometryAny` を選ぶ。

PRF は、同じ iCloud Keychain passkey を持つ別デバイスで vault を可搬にすること自体が要件なら有力である。ただし、その可搬性は同時に攻撃面も Apple Account・同期済みデバイス・passkey recovery へ広げる。また native API は macOS 15 以降で、Rust binding の整備度と daemon からの ASAuthorization UI ライフサイクルが Secure Enclave 案より未成熟である。PRF を採る場合は「同期可搬 vault」を別モードとして設計し、platform passkey の登録・喪失・複数 credential・recovery を先に仕様化するのがよい。

PRF 出力を直接 AEAD key に固定せず、HKDF で `vault-id`、schema version、用途 label を context に含めて鍵分離する。salt は公開値でよいが、vault ごとにランダム生成して暗号文 header に保存する。credential ID と RP ID への依存を recovery metadata に明記する。

## 検証の詳細

### AuthenticationServices SDK header

確認対象:

- `AuthenticationServices.framework/Headers/ASAuthorizationPlatformPublicKeyCredentialAssertionRequest.h`
- `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.h`
- `ASAuthorizationPlatformPublicKeyCredentialAssertion.h`
- `ASAuthorizationPlatformPublicKeyCredentialRegistration.h`
- `ASAuthorizationPublicKeyCredentialPRFAssertionInput.h`
- `ASAuthorizationPublicKeyCredentialPRFAssertionOutput.h`
- `ASAuthorizationPublicKeyCredentialPRFRegistrationInput.h`
- `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput.h`

| 項目 | header で確認した結果 |
|---|---|
| platform assertion request | `prf` property、macOS 15.0+ |
| platform assertion result | `prf` output、macOS 15.0+ |
| platform registration request/result | `prf` input/output、macOS 15.0+ |
| 入力 | 1 個または 2 個の salt、全 credential 共通または credential ID ごと |
| 出力 | `first` と任意の `second` |
| capability check | registration input の `checkForSupport` と output の `isSupported` |
| largeBlob | read/write operation、macOS 14.0+ |
| security key PRF | 確認 SDK では macOS 26.4+ |

Apple Developer Documentation の対応ページ:

- [ASAuthorizationPlatformPublicKeyCredentialAssertionRequest](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialassertionrequest)
- [ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialregistrationrequest)
- [ASAuthorizationPublicKeyCredentialPRFAssertionInput](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput)
- [ASAuthorizationPublicKeyCredentialPRFAssertionOutput](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertionoutput)
- [ASAuthorizationPublicKeyCredentialPRFRegistrationInput](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfregistrationinput)
- [ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentiallargeblobassertioninput)

GitHub 上の native PRF 実装例は本調査で確度の高いものを確認できなかった。Apple の passkey sample は AuthenticationServices assertion のライフサイクル理解には使えるが、PRF 使用例を含むことは未確認である。

### PRF の暗号学的性質と User Verification

一次資料:

- [W3C WebAuthn Level 3: Pseudo-random function extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [W3C WebAuthn Level 3: CTAP2 hmac-secret extension](https://www.w3.org/TR/webauthn-3/#sctn-hmac-secret-extension)
- [W3C WebAuthn Level 3: User Verification Requirement](https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement)
- [Apple: ASAuthorizationPublicKeyCredentialUserVerificationPreference](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialuserverificationpreference)

| 論点 | 結果 |
|---|---|
| 決定性 | credential 固有秘密と domain-separated input が同じなら同じ値 |
| 出力数 | 1 回に最大 2 値。Apple API の `first` / `second` と対応 |
| UV | RP は preference を指定できるが、PRF API 自体に「必ず biometric」の独立フラグはない |
| UI | ASAuthorization assertion の UI lifecycle に従う。Touch ID の毎回発火は未確認 |

実機での passkey 登録、assertion、Touch ID 観測は依頼の禁則に従い実施していない。

### iCloud Keychain 同期

一次資料:

- [Apple Platform Security: Passkeys security](https://support.apple.com/guide/security/passkeys-security-sec3e341e75d/web)
- [Apple Platform Security: Secure keychain syncing](https://support.apple.com/guide/security/secure-keychain-syncing-sec0a319b35f/web)
- [W3C WebAuthn Level 3: Multi-device credentials](https://www.w3.org/TR/webauthn-3/#multi-device-credentials)

Apple は passkey が iCloud Keychain を通して end-to-end encrypted に同期されることを説明している。WebAuthn は backup-eligible credential source を multi-device credential と定義する。ただし、Apple 文書内の PRF 固有の byte-level 同一性保証は確認できなかったため、次を未確認として残す。

- macOS 15、現行 macOS、iOS の少なくとも 3 category で、同じ synced passkey と同じ入力から `first` が一致する実機マトリクス。
- passkey provider が iCloud Keychain 以外の場合の PRF secret 同期方針。
- account recovery または passkey migration 後も同一 credential source として PRF 値が維持されるか。

### Secure Enclave 対抗案

一次資料:

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [Apple: SecAccessControlCreateWithFlags](https://developer.apple.com/documentation/security/1392871-secaccesscontrolcreatewithflags)
- [Apple: SecAccessControlCreateFlags.biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)
- [Apple: SecAccessControlCreateFlags.biometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany)
- [Apple: LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)

| 評価軸 | Passkey PRF | Secure Enclave + biometric ACL |
|---|---|---|
| 可搬性 | synced passkey なら別デバイス利用を期待できる | 端末固定。key は export/sync 不可 |
| 攻撃面 | Apple Account、同期端末、recovery、credential provider を含む | 当該端末、Secure Enclave、login session、biometric policy に限定 |
| 鍵の性質 | credential secret から salt ごとの 32-byte PRF 値 | non-exportable private key でランダム vault key を wrap |
| biometric policy | assertion の UV preference。biometric 固有 ACL ではない | `biometryCurrentSet` / `biometryAny` を key 使用条件にできる |
| UI 発火点 | ASAuthorization assertion 時。OS 主導 | private-key operation 時。`LAContext` で理由文・再利用等を設定可能 |
| API 成熟度 | native は macOS 15+ | Security/LocalAuthentication の長年の API |
| Rust 利用 | `objc2` 直結・bindings 補完が必要 | `security-framework(-sys)` + 必要箇所の raw FFI |
| recovery | passkey の同期・回復設計に依存 | key 喪失・biometry set 変更時は unwrap 不可。明示 recovery 必須 |

Secure Enclave の EC key は一般の symmetric key store ではないため、vault key を Enclave に直接保存するのではなく、ランダムな symmetric vault keyを Enclave public key で保護する構成にする。

### Rust からの利用経路

参照:

- [`objc2` project](https://github.com/madsmtm/objc2)
- [`objc2-authentication-services` on docs.rs](https://docs.rs/objc2-authentication-services/)
- [`objc2-local-authentication` on docs.rs](https://docs.rs/objc2-local-authentication/)
- [`security-framework` on docs.rs](https://docs.rs/security-framework/)
- [`security-framework-sys` on docs.rs](https://docs.rs/security-framework-sys/)

`objc2-authentication-services` の公開 version が PRF 型を生成済みかは未確認である。無い場合でも Objective-C runtime の型・selector を局所 wrapper に閉じ込めれば実装可能だが、availability check、main-thread/UI lifecycle、delegate callback、NSData ownership を安全な Rust API に封じる必要がある。

Secure Enclave 経路は `SecKeyCreateRandomKey` / `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData` または key agreement API、Keychain query、`SecAccessControl` を組み合わせる。Rust crate の high-level coverage を実装前に inventory し、不足分だけ `security-framework-sys` または自前 `extern "C"` に落とす。

### 未確認項目

- Apple 公式 WWDC セッション内で PRF native API を明示的に説明した箇所と timestamp。
- Apple または広く利用される OSS の native PRF 完成実装例。
- synced passkey の別デバイス PRF 出力一致を Apple が明文保証する資料。
- macOS daemon の activation policy・foreground UI 制約下で ASAuthorization assertion を安定して提示できるか。
- `userVerificationPreference` の 3 値と、Touch ID、Apple Watch、password fallback、recent-authentication cache の実機 UI マトリクス。
- 現行 `objc2-authentication-services` と `security-framework` の API coverage の compile PoC。
