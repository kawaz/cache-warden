# FDA チェック & 誘導フローの移植（authsock-warden → cache-warden）

- status: open
- 記録: 2026-06-14（kawaz 指摘。authsock-warden で解決済みだが cache-warden 未対応）
- last_read: 2026-06-22T20:37:32+09:00
- 知見 doc: [2026-06-14-macos-tcc-fda.md](../findings/2026-06-14-macos-tcc-fda.md)
- 関連: DR-0019（daemon register）/ DR-0020（.app + AssociatedBundleIdentifiers、TCC 永続化の前提は実装済み）

## 問題

cache-warden daemon が `op` CLI を実行すると、macOS で **新バイナリ（responsible process のパス変化）ごとに TCC ダイアログ**（他アプリのデータへのアクセス確認）が出る。op:// ソース利用時に毎回・アップグレード毎に発生し、離席中の TouchID/ダイアログ連発の一因。

DR-0020 で .app + AssociatedBundleIdentifiers による Bundle ID ベースの TCC 永続化**自体は実装済み**だが、**Full Disk Access (FDA) を ON にするようユーザーを誘導するフロー**が未移植。FDA を ON にすれば AppData を包含してダイアログが恒久的に消える（知見 doc 参照）。

## authsock-warden の解（移植元 = `src/cli/commands/service.rs`）

`daemon register`（service register）に統合された FDA セットアップフロー:

1. `has_op_sources(config)` — config に op:// ソースがある時だけ FDA を要求（service.rs:510）
2. `check_fda_with_retry()` — 3 回リトライ（app 起動レイテンシ吸収、1s 間隔）（:520）
3. `check_fda_via_app()` — **`.app` として FDA をチェック**（:534）:
   - `find_app_bundle(current_exe)` で `.app` ルートを解決（cache-warden は既存 `app_bundle_path()` 流用可、service.rs:116）
   - `open --wait-apps <app> --args internal fda-check --raw --result-file <tmp>` で .app 起動 = 正しい TCC identity でチェック + **FDA リストへ自動追加**
   - `open` の stderr は `/dev/null`（LSBackgroundOnly のノイズ抑制）
   - result-file が `"ok"` なら FDA 付与済み
4. `internal fda-check` サブコマンド — 実体のチェック。`/Library/Application Support/com.apple.TCC/TCC.db` の `std::fs::metadata` 成否で判定し、`--result-file` に `ok`/否を書く（`--raw` は .app 再起動せず直接チェック）
5. `prompt_fda_setup()` — FDA 未付与なら誘導（:600）:
   - `open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"` で System Settings の FDA ページを開く
   - 2 秒間隔で `check_fda_via_app()` をポーリング、ON 検出で自動的に次へ
   - `wait_for_fda_or_enter()`（:652）: ポーリング or Enter 待ち。Enter（未付与）なら「起動/アップグレード毎に TCC ダイアログが出る、後で register 再実行を」と警告して続行
   - 終了時 osascript で System Settings を閉じる

README にも「macOS: Full Disk Access」節（未設定なら register 時に自動案内、未許可でも動作するが毎回ダイアログ）がある。

## cache-warden への移植計画

- **`internal fda-check` サブコマンド追加**（`--raw` / `--result-file`）: TCC.db metadata チェック。`commands/` に internal グループ or daemon サブに。
- **`check_fda_via_app` / `check_fda_with_retry` / `prompt_fda_setup` / `wait_for_fda_or_enter` / `has_op_sources`** を `commands/service.rs` に移植（`#[cfg(target_os = "macos")]`）。`find_app_bundle` は既存 `app_bundle_path()` を流用。
- **`daemon register` フローに統合**: plist 書込み後・サービス起動前に `has_op_sources && !check_fda_with_retry → prompt_fda_setup`。
- **README（ja 正本 + en）に FDA 節を追加**。
- op:// ソースの検出は cache-warden の config 構造（型付き source `op.uri`、authsock keys）に合わせる（authsock-warden の `members.starts_with("op://")` とは構造が違うので要調整）。

## 注意（実装は実機テスト必須）

FDA の検出（TCC.db read）/ .app 経由起動 / System Settings 誘導 / ポーリングは **macOS で FDA を ON/OFF トグルしながらの実機テストが必須**。無検証では出荷しない。kawaz 在席で FDA トグル確認できる時に実装するのが安全。

## 決定の所属

移植判断・FDA 誘導 UX は DR 級（DR-0019/0020 の macOS 系列に連なる）。実装着手時に DR 化を検討。
