# daemon プロセスは notarization 済みバイナリ + FDA 許可

cache-warden の **daemon プロセス** (= `cache-warden daemon run`、launchd で
常駐する側) は原則 **notarization 済みバイナリ** (`/Applications/CacheWarden.app/Contents/MacOS/cache-warden`) を使う。**加えて Full Disk Access (FDA) の TCC 許可も必要** (= `kTCCServiceSystemPolicyAppData`)。

## なぜ (= 2 つ揃って初めて dialog が消える)

未署名 / 未 notarize の dev build を daemon として走らせると、Gatekeeper /
TCC のダイアログが頻発して dogfood 体験を壊す。

しかし **notarize だけでは不十分**。cache-warden が op CLI を spawn → op CLI が
1Password app の AppData にアクセス → macOS が `kTCCServiceSystemPolicyAppData`
(= Full Disk Access) を要求 → cache-warden が責任主体として「他のアプリケーション
にアクセスしようとしています」相当の dialog をユーザに出す。これは notarize の
有無と無関係に、**FDA 許可を System Settings → Privacy & Security → Full Disk
Access に明示登録するまで続く**。

### 観測 (2026-06-22)

```
tccd: AUTHREQ_PROMPTING: msgID=..., service=kTCCServiceSystemPolicyAppData,
  subject=Sub:{com.github.kawaz.cache-warden}
  Resp:{TCCDProcess: identifier=com.github.kawaz.cache-warden, ...
        binary_path=/Applications/CacheWarden.app/Contents/MacOS/cache-warden},
  accessing={TCCDProcess: identifier=com.1password.op, ...}
```

= notarize 済 app から op CLI を spawn しただけで FDA dialog が出る。FDA 許可
されるまで起動のたびに再発し得る。

## 適用範囲

- **daemon プロセス** (= 常駐する `cache-warden daemon run`):
  - 原則 app 版を使う (notarize 済み)
  - System Settings → Privacy & Security → **Full Disk Access** に `CacheWarden.app` を追加 (FDA ON)
  - DR-0020 で `.app` + `AssociatedBundleIdentifiers` による TCC 永続化は完了済み、FDA ON で AppData を包含 → dialog 恒久消去 (findings/2026-06-14-macos-tcc-fda.md)
- **未実装の誘導フロー**: cache-warden の `daemon register` フロー終盤で FDA 未付与時に System Settings 誘導 + ポーリングする。authsock-warden の `src/cli/commands/service.rs` に既実装、cache-warden 移植は `docs/issue/2026-06-14-fda-check-flow-port.md` で管理
- **開発中の CLI バイナリ** (= 短時間で終わる `cache-warden status` / `cache-warden kv list` 等): ローカルビルドで OK
  - PATH 上の `cache-warden` (homebrew or `cargo install`) が dev build でも実害なし
  - 単発実行で終わるので Gatekeeper ダイアログが頻発しない

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
