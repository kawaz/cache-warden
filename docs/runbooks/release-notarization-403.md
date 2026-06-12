# Runbook: Apple notarization が 403 "agreement missing or has expired" で失敗する

- Last Updated: 2026-06-12

> 出典: authsock-warden の同名 runbook を cache-warden 文脈に移植 (warden は archive 予定のため
> リンクでなくコピー)。背景知識は [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) を参照。

## 症状

GitHub Actions の release ワークフロー (`.github/workflows/release.yml` の
`Build (*-apple-darwin)` ジョブ → `Notarize binary (macOS)` ステップ) で次のエラーで失敗する:

```
xcrun notarytool store-credentials "notary-profile" \
  --apple-id "$APPLE_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" \
  --team-id "$APPLE_TEAM_ID"
...
Validating your credentials...
Error: HTTP status code: 403. A required agreement is missing or has expired.
This request requires an in-effect agreement that has not been signed or has expired.
```

`store-credentials` が `Validating your credentials...` を出した直後に 403 を返す。

Linux ビルドが先に完走していた場合、fail-fast で `aarch64-apple-darwin` 等が `cancelled` に
なることもある (macOS 側が原因なのは変わらない)。

## 即断する判断根拠 (これが揃ったら 99% この事象)

1. **コードや CI スクリプト・Secrets を直前に変えていない**のに突然失敗する
2. notarize ステップだけ失敗、ビルド・テストは成功
3. エラーメッセージに `agreement` という単語が含まれる
4. 過去に同じワークフローでリリースが成功している実績がある

これらが揃ったら **Apple Developer Program License Agreement (PLA) の再同意が必要**。
コード側は触らない。

## 紛らわしい別系統エラー (除外用チェックリスト)

| エラーメッセージ断片 | 真の原因 | 対処 |
|---|---|---|
| `A required agreement is missing or has expired` | **PLA 再同意 (本ケース)** | このランブックの解決手順へ |
| `Invalid credentials` / `authentication failed` | App-Specific Password の失効・タイポ | appleid.apple.com で再生成して GitHub Secret 更新 ([apple-signing-secrets-setup](./apple-signing-secrets-setup.md)) |
| `The team you specified is not active` | Apple Team / Membership 状態 | Membership 課金状況の確認 |
| `Your account does not have permission` | Account Holder 以外で操作 | ロール確認 (Account Holder のみ可) |
| `invalid Apple ID or password` | Apple ID 自体の問題 | Apple ID パスワード再確認 |

## 解決手順

1. <https://developer.apple.com/account> に Apple ID でサインイン
2. トップに **黄色/赤の警告バナー**が出ているか確認 (出ていない場合は別系統エラーを疑う)
3. 「Agreements」セクションで未同意の規約に Agree
4. `gh run rerun <run_id> --failed --repo kawaz/cache-warden` で macOS の失敗ジョブのみ再実行

```bash
# 直近の失敗 release run
run_id=$(gh run list --repo kawaz/cache-warden --workflow=release.yml --status=failure --limit 1 --json databaseId -q '.[0].databaseId')
gh run rerun "$run_id" --failed --repo kawaz/cache-warden
```

5. CI 完走後、`brew upgrade --cask kawaz/tap/cache-warden` → `cache-warden daemon register`
   で plist を貼り直す (DR-0019)
   - macOS では .app 内バイナリの絶対パスを指す plist を作り直すことで、brew upgrade 後の
     パス変化に追従させる
   - もし `daemon status` で表示される実行ファイルが .app 内パス以外 (例: 過去にローカルビルドで
     register した名残) を指していたら、明示的に `cache-warden daemon register` を呼んで
     plist を作り直す

## 補足

- Apple は規約改定のたびに再同意を要求する。**年に 1〜数回**は発生する想定でよい
- `noreply@email.apple.com` から「You must agree to the latest agreement」の通知が届く
  (迷惑メールに入りやすい)
- 個人 Developer Program でも法人 Team でも同じエラー文言。同意ボタンは
  **Account Holder ロール** にしか出ない
- 同意してから notarytool が認識するまでは通常 1 分以内
- release CI の trigger は `paths: [Cargo.toml]` なので、コミットを足さずに
  `gh run rerun --failed` で再発火させる (`Cargo.toml` を不必要に bump しない)

## 関連

- [apple-signing-secrets-setup](./apple-signing-secrets-setup.md) — Apple secrets の新規発行・投入手順
- [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) — 署名・notarization・.app バンドルの設計
