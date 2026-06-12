# macOS TCC / responsible process と .app バンドルの知見

- Last Updated: 2026-06-12

> 出典: authsock-warden の `docs/macos-tcc-fda.md` / `DR-012-app-bundle-wrapper.md` の実証知見を
> cache-warden 文脈に要約移植 (warden は archive 予定のためリンクでなくコピー)。設計判断は
> [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) を参照。

## 判明した事実

1. **LaunchAgent 経由で常駐するバイナリが op CLI 等を呼ぶと、TCC の責任プロセス (responsible
   process) が「バイナリの実体パス」になる**。Homebrew のバージョン付きディレクトリにインストール
   されていると、`brew upgrade` のたびにパスが変わり TCC 許可が失われ、承認ダイアログが再発する。
2. **codesign 済みでもこの問題は解決しない**。LaunchAgent 経由ではパスベース識別から逃れられない。
3. **.app バンドル + `AssociatedBundleIdentifiers` で responsible process を Bundle ID ベースに
   切り替えると、パスが変わっても許可が永続化される**。これが採用解 (DR-0020 / warden DR-012)。
4. **symlink でパスを安定化させる案は効かない** (warden v0.1.11 で実証済みの失敗)。macOS は
   TCC チェック時に symlink を実体パスへ解決するため、責任プロセスは実体パスのままになる。
5. **codesign はボトムアップ (バイナリ → .app の順) で行う。`--deep` は使わない**。`--deep` は
   ネストされたバンドルの署名順序を保証せず Apple も非推奨。
6. **notarization には codesign が必須**。TCC の Bundle ID ベース識別自体は codesign の有無に
   関わらず動くが、Gatekeeper を通すには Developer ID 署名 + notarize + staple が要る。

## 実用的な示唆

- cache-warden の macOS リリースは `CacheWarden.app` (Bundle ID =
  `com.github.kawaz.cache-warden`) を必須とし、tarball に .app と素バイナリの両方を含める。
- `daemon register` (DR-0019) は macOS で .app 内実行を検出したら launchd plist に
  `AssociatedBundleIdentifiers` を入れ、ProgramArguments を .app 内バイナリの絶対パスにする。
  素バイナリから register した場合は TCC 永続化が効かない (開発時用)。
- Info.plist は `LSBackgroundOnly = true` にして Dock 非表示・GUI なしのバックグラウンド
  サービスとして振る舞わせる。

## 背景: TCC と responsible process

TCC (Transparency, Consent, and Control) は macOS のプライバシー保護フレームワーク。保護された
リソース (他アプリのデータ等) へのアクセスに対し、要求した「責任プロセス」単位で許可を管理する。
責任プロセスの決定は起動経路に依存する:

| 起動経路 | 責任プロセス | 許可の永続性 |
|---|---|---|
| Terminal.app → shell → バイナリ | `com.apple.Terminal` (Bundle ID) | 永続 (Terminal を一度許可すれば良い) |
| launchd → バイナリ (素) | バイナリの実体パス | brew upgrade でパスが変わると失われる |
| launchd → `*.app/Contents/MacOS/` 内バイナリ | .app の Bundle ID | 永続 (パス変化に耐える) |

cache-warden の主要ユースケースは LaunchAgent 常駐 (daemon)。LaunchAgent 経由では TCC 問題が
必ず起きるため、macOS では .app バンドルが実質必須になる。

## .app バンドルと launchd plist の連携

```
CacheWarden.app/
  Contents/
    Info.plist            # CFBundleIdentifier = com.github.kawaz.cache-warden, LSBackgroundOnly = true
    MacOS/
      cache-warden        # 実行バイナリ
```

launchd plist 側に以下を入れると、launchd がプロセスを .app の Bundle ID に関連付ける:

```xml
<key>AssociatedBundleIdentifiers</key>
<array>
    <string>com.github.kawaz.cache-warden</string>
</array>
```

ProgramArguments は .app 内バイナリの絶対パス (`.../CacheWarden.app/Contents/MacOS/cache-warden`)
を指す。

## 補足: FDA (Full Disk Access)

- `kTCCServiceSystemPolicyAllFiles` (FDA) は `kTCCServiceSystemPolicyAppData` を包含する。
  FDA を System Settings で ON にすれば個別の AppData 許可は不要。
- FDA 許可は responsible process (= .app の Bundle ID) に対して付与される。.app を `open` で
  起動すると macOS が自動的にその .app を FDA リスト (System Settings > Privacy & Security >
  Full Disk Access) に追加する (ON にするのはユーザ操作)。
- システムの TCC DB (`/Library/Application Support/com.apple.TCC/TCC.db`) は読み取り自体に FDA が
  必要。`std::fs::metadata` の成否で FDA 状態を判定できるが、「OFF」と「未登録」は区別できない。

## 関連

- [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) — 署名・notarization・.app バンドルの設計
- [DR-0019](../decisions/DR-0019-daemon-service-registration.md) — daemon サービス登録 (.app 検出と AssociatedBundleIdentifiers)
- [release-notarization-403](../runbooks/release-notarization-403.md) — notarize 失敗時の診断
- [apple-signing-secrets-setup](../runbooks/apple-signing-secrets-setup.md) — 署名 secrets の投入
