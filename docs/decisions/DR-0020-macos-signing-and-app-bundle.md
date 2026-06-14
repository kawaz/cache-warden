# DR-0020: macOS 署名・notarization と .app バンドル

- Status: Active
- Date: 2026-06-12

## Context

macOS では署名 identity が安定しないバイナリが op CLI を呼ぶと、バイナリ更新のたびに
TCC / 承認ダイアログが再表示される。authsock-warden はこれを 2 層で解決済みであり、
warden は将来 archive されるため、その実装とノウハウを cache-warden に移植して
こちらを正とする。

warden の実証済み知見 (出典: warden DR-012 / release.yml / runbooks):

1. **codesign (Developer ID) + notarization + staple**: バイナリの identity を署名で
   安定させる。ad-hoc 署名はビルドごとに別プログラム扱い。
2. **.app バンドルラッパー (warden DR-012)**: LaunchAgent 起動では TCC の responsible
   process が**パスベース**になり、codesign 済みでも brew upgrade でパスが変わると
   許可が飛ぶ。`.app` の Bundle ID ベースに切り替えるには .app 構造 +
   launchd plist の `AssociatedBundleIdentifiers` が必要。
   **symlink 経由でのパス安定化は TCC が実体パスへ解決するため効かない**
   (warden v0.1.11 で実証済みの失敗)。

## Decision

### 1. .app バンドル `CacheWarden.app`（macOS リリース必須）

```
CacheWarden.app/
  Contents/
    Info.plist            # CFBundleIdentifier = com.github.kawaz.cache-warden
    MacOS/
      cache-warden        # 実行バイナリ
```

- リリース tarball には **.app と素のバイナリの両方**を含める (warden と同じ。
  Homebrew が単一トップレベルディレクトリを auto-strip する問題の回避を兼ねる)。
- `daemon register` (DR-0019) は macOS で、自分が .app 内 (`*.app/Contents/MacOS/`)
  から実行されている場合に plist へ `AssociatedBundleIdentifiers` を入れ、
  ProgramArguments は .app 内バイナリの絶対パスを指す。素のバイナリから register した
  場合は従来どおり (開発時用。TCC 永続化は効かない旨を register が 1 行 hint)。

### 2. release.yml の署名・notarization パイプライン（warden 移植）

macOS ビルドジョブに追加 (warden release.yml と同構成):

1. 一時 keychain 作成 → `APPLE_CERTIFICATE_BASE64` (p12) を import
2. `codesign --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp` を
   **バイナリ → .app の順 (bottom-up)** で実行
3. `notarytool store-credentials` → `submit --wait` → `stapler staple`
4. keychain を `always()` でクリーンアップ

### 3. GitHub Secrets はプロダクト別（kawaz 確定）

warden の secrets を使い回さず、cache-warden 用に**新規発行**する:

| Secret | 入手元 | 備考 |
|---|---|---|
| `APPLE_ID` | Apple ID (共通値) | |
| `APPLE_TEAM_ID` | Developer アカウント (共通値) | |
| `APPLE_APP_SPECIFIC_PASSWORD` | appleid.apple.com で **cache-warden 用に新規発行** | プロダクト別にする主対象。漏洩時の rotate 単位 |
| `APPLE_CERTIFICATE_BASE64` | Developer ID Application 証明書の p12 (base64) | 証明書自体は Team の既存を流用可、p12 は再エクスポート |
| `APPLE_CERTIFICATE_PASSWORD` | p12 エクスポート時に設定 | |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: ...` (共通値) | |

secrets 投入は kawaz の手作業 (App-Specific Password 発行・p12 エクスポートは
Apple ID / Keychain 操作が必要)。手順は runbook 化する (§4)。

### 4. ノウハウの移植（warden archive に備える）

warden の以下を cache-warden の docs にこちらの文脈で書き直して**移植済み**
(リンクでなくコピー。warden は archive ルートのため):

- `docs/runbooks/release-notarization-403.md` — PLA 再同意 403 の診断と対処
  （エラー分類表ごと移植済み）
- `docs/findings/2026-06-12-macos-tcc-responsible-process.md` — TCC / responsible process
  の背景知識（macOS TCC の動作・Bundle ID ベース判定の実証知見を記録）
- `docs/runbooks/apple-signing-secrets-setup.md` — secrets セットアップ手順: App-Specific
  Password 発行 → p12 エクスポート → `gh secret set` の一連（移植済み）

## Alternatives Considered

- **warden の secrets を使い回す**
  - 不採用理由 (kawaz 確定): プロダクト別にすることで漏洩時の影響範囲と rotate 単位が
    プロダクトに閉じる。warden archive 時に secrets を無効化しても cache-warden に
    影響しない。
- **ad-hoc 署名 + ユーザ側で都度許可**
  - 不採用理由: バイナリ更新ごとにダイアログが出る現状の問題そのもの。
- **symlink でパス安定化 (.app なし)**
  - 不採用理由: TCC は symlink を実体パスに解決する (warden v0.1.11 の実証済み失敗)。
- **Linux でも同等の仕組み**
  - 不要: TCC は macOS 固有。Linux は何もしない (cfg 分岐)。

## Consequences

- release.yml の macOS ジョブに署名・notarization が実装済みで、リリースには
  cache-warden 用 Apple secrets の事前投入が必要（runbooks/apple-signing-secrets-setup.md
  の手順で投入）。
- `daemon register` (DR-0019) に .app 検出と `AssociatedBundleIdentifiers` が実装済み。
- Homebrew cask/formula は .app 入り tarball を配る形（配布詳細は別途）。
- warden の notarization 知見は cache-warden の docs が正本。TCC / responsible process
  の背景知見は `docs/findings/2026-06-12-macos-tcc-responsible-process.md` を参照。

## 関連

- [DR-0019-daemon-service-registration](./DR-0019-daemon-service-registration.md) — register の .app 対応
- warden DR-012 (.app バンドルラッパー) / release.yml / release-notarization-403 runbook — 移植元 (archive 予定)
