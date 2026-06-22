# daemon プロセスは notarization 済みバイナリを使う

cache-warden の **daemon プロセス** (= `cache-warden daemon run`、launchd で
常駐する側) は原則 **notarization 済みバイナリ** (`/Applications/CacheWarden.app/Contents/MacOS/cache-warden`) を使う。

## なぜ

未署名 / 未 notarize の dev build を daemon として走らせると macOS の
セキュリティダイアログ (Gatekeeper / TCC) が頻発して dogfood 体験を壊す。
daemon は常駐するので、起動・実行のたびにダイアログが出ると鬱陶しい。

## 適用範囲

- **daemon プロセス** (= 常駐する `cache-warden daemon run`): 原則 app 版
  - 通常の dogfood 中は `/Applications/CacheWarden.app` 経由で launchd 稼働
  - dev build を daemon として走らせるのは「変更を実機で検証する明示意図」がある時だけ
- **開発中の CLI バイナリ** (= 短時間で終わる `cache-warden status` / `cache-warden kv list` 等): ローカルビルドで OK
  - PATH 上の `cache-warden` (homebrew or `cargo install`) が dev build でも実害なし
  - 単発実行で終わるので Gatekeeper ダイアログが頻発しない

## How to apply

- daemon の挙動検証で「コードの修正を反映したい」場合は、まず**修正済み app
  をビルド + sign + notarize して再インストール**してから稼働 daemon を再起動する
- 緊急で dev build daemon を使うときは kawaz に明示確認、検証後すぐ app daemon に戻す
- launchctl で稼働中の daemon が指すバイナリを確認するときは:

```bash
daemon_pid=$(launchctl print gui/$(id -u)/com.github.kawaz.cache-warden \
  | awk '/^\tpid =/ { print $3 }')
lsof -p "$daemon_pid" | awk 'NR==1 || /MacOS\/cache-warden/'
```

`/Applications/CacheWarden.app/Contents/MacOS/cache-warden` を掴んでいれば app 版。

## 関連

- DR-0019 (daemon register / launchd) — daemon 登録経路
- [[release-flow-awareness]] (claude-rules-personal) — 自動リリースフロー (app 版のビルド経路)
