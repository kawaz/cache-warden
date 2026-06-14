# macOS TCC / FDA 技術知見（authsock-warden から移植）

cache-warden が `op` CLI を実行する際、macOS では **新バイナリごとに TCC ダイアログ**（他アプリのデータへのアクセス確認）が出る問題がある。authsock-warden は **Full Disk Access (FDA) のチェック & 誘導フロー**でこれを解消済み。本 doc はその過程で判明した TCC の挙動知見を cache-warden に移植したもの（出典: authsock-warden `docs/macos-tcc-fda.md`）。

実装の移植（`fda-check` 相当 + `daemon register` への FDA 誘導統合）は別 issue
[2026-06-14-fda-check-flow-port](../issue/2026-06-14-fda-check-flow-port.md) を参照。

## 判明した事実（要約）

- `op` CLI が 1Password データ（`~/Library/Group Containers/`）にアクセスすると TCC カテゴリ **AppData** がトリガーされる。
- **LaunchAgent 経由では AppData 許可が永続化されず、サービス起動/アップグレードのたびにダイアログが出る**。
- **FDA（AllFiles）を System Settings で ON にすれば AppData を包含して永続的に解決**する（DR-0020 の .app + AssociatedBundleIdentifiers で Bundle ID ベースに永続化されることが前提）。
- FDA は responsible process（= アプリ）単位で付与される。正しいアプリ（CacheWarden.app）の FDA を扱うには **`.app` として起動**してチェック・追加する必要がある。

## TCC の概要

TCC (Transparency, Consent, and Control) は macOS のプライバシー保護フレームワーク。保護リソース（カメラ/マイク/他アプリのデータ等）へのアクセスにユーザー許可を求める。許可情報は TCC データベースに保存される:

| データベース | パス | スコープ |
|---|---|---|
| ユーザー | `~/Library/Application Support/com.apple.TCC/TCC.db` | ユーザー固有の許可 |
| システム | `/Library/Application Support/com.apple.TCC/TCC.db` | システム全体の許可（FDA 等） |

## Responsible Process（起動経路で決まる）

TCC はアクセスを要求した responsible process に対して許可を管理する。決定方法は起動経路依存（詳細は [responsible-process findings](./2026-06-12-macos-tcc-responsible-process.md) も参照）:

- **Terminal.app から実行**: responsible = `com.apple.Terminal`（Bundle ID、永続化される）
- **LaunchAgent から素バイナリ実行**: responsible = バイナリのパス（Homebrew Cellar のバージョン付きパスはアップグレードで変わり許可が失われる）
- **.app バンドルから実行**: responsible = `com.github.kawaz.cache-warden`（Bundle ID、パス変更に強い）
- **`open` コマンド経由**: `open /Applications/CacheWarden.app --args ...` で起動すると macOS は .app を「アプリ」と認識し responsible = Bundle ID になる（CLI 直接実行と異なる挙動）

## TCC カテゴリと包含関係

- **kTCCServiceSystemPolicyAppData**（他アプリのデータへのアクセス権）: 対象 `~/Library/Group Containers/` 等。op が 1Password データにアクセスする際にトリガー。**LaunchAgent 経由では永続化されない**（毎回ダイアログ）。
- **kTCCServiceSystemPolicyAllFiles**（Full Disk Access / FDA）: ファイルシステム全体。AppData を包含。**System Settings で ON にすれば永続**（ダイアログでなく明示操作が必要）。

```
FDA (AllFiles)
 └── AppData
 └── その他の保護カテゴリ（一部）
```

FDA を ON にすれば AppData の個別許可は不要。

## FDA のチェック方法

### TCC データベースの読み取り試行

```rust
let tcc_db = std::path::Path::new("/Library/Application Support/com.apple.TCC/TCC.db");
let has_fda = std::fs::metadata(tcc_db).is_ok();
```

システム TCC DB の読み取り自体に FDA が要るため、metadata 取得の成否で FDA 状態を判定できる。OFF と未登録は区別できない（どちらも失敗）。

### .app コンテキストでのチェック（重要）

FDA は responsible process（アプリ）に付与されるので、正しいアプリ（CacheWarden.app）の FDA をチェックするにはそのアプリとして起動する:

```bash
# CLI 直接 → Terminal.app の FDA を見てしまう（誤り）
cache-warden internal fda-check

# .app として起動 → CacheWarden.app の FDA を見る（正しい）
open --wait-apps /Applications/CacheWarden.app --args internal fda-check --raw
```

## FDA リストへの自動追加

`.app` を `open` で起動すると macOS は自動的にその .app を FDA リスト（System Settings > Privacy & Security > Full Disk Access）に追加する:
- ユーザーが「+」で手動追加する必要がない
- 追加時点では OFF。ユーザーがトグルを ON にする必要がある
- register 時の `check_fda_via_app()` 呼び出しがこの自動追加を兼ねる

## System Settings の FDA ページを開く

```bash
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
```

authsock-warden は register 時にこれで FDA ページを開き、2 秒間隔で許可をポーリングし、ON 検出で自動的に次へ進む。開いた System Settings は osascript（`tell application "System Settings" to quit`）で閉じる。

## .app バンドルと Bundle ID

```xml
<key>CFBundleIdentifier</key>
<string>com.github.kawaz.cache-warden</string>
<key>LSBackgroundOnly</key>
<true/>
```

`LSBackgroundOnly = true` で Dock 非表示・GUI ウィンドウ無しのバックグラウンドサービスになる。LaunchAgent plist 側の `AssociatedBundleIdentifiers` で launchd がプロセスを Bundle ID に関連付ける（DR-0019/DR-0020 で実装済み）。

## LSBackgroundOnly アプリの `open --wait-apps` のノイズ

`LSBackgroundOnly = true` の .app を `open --wait-apps` で起動すると、stderr に:

```
Unable to find a bundle for com.github.kawaz.cache-warden to block on.
```

が出る。これは GUI イベントループ（NSApplication）を持たないことに起因し、動作は正常。**対処**: stderr を `/dev/null` にリダイレクトして抑制する。

## コード署名との関係

- TCC の Bundle ID ベース識別は codesign の有無に関わらず動作する
- Notarization には codesign が必須（DR-0020）
- codesign はボトムアップ（バイナリ → .app）。`--deep` は使わない

## 関連

- [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) — .app + AssociatedBundleIdentifiers で TCC を Bundle ID ベース化（永続化の前提）
- [2026-06-12-macos-tcc-responsible-process.md](./2026-06-12-macos-tcc-responsible-process.md) — responsible process の原調査
- [issue/2026-06-14-fda-check-flow-port.md](../issue/2026-06-14-fda-check-flow-port.md) — 実装（fda-check + register 誘導）の移植計画
- 出典: authsock-warden `docs/macos-tcc-fda.md`
