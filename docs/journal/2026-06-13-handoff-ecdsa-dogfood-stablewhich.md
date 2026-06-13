# handoff: ECDSA / dogfood 切替 / stable-which 連携 — 次セッションへ

- Date: 2026-06-13

前セッション (Opus 4.8 メイン) からの引き継ぎ。設計 DR を多数積み実装、v0.19.1 まで
リリース。本 journal 起点で続きを進める。

## 最優先で読む / 最初にやること

1. **ECDSA がローカルコミット済みだが未 push** (commit `be30fea4`)。`just ci` が
   この macOS で 1 件失敗して push を止めている (下記「CI ブロッカー」)。次セッションは
   まず CI ブロッカーを解消 → `just bump-version minor` → `just push`。
2. **dogfood 切替が現在 ON** (cache-warden が日常 SSH の本番)。daemon 稼働中。
   挙動がおかしければロールバック手順 (下記) で authsock に即戻せる。

## 現在の稼働状態 (dogfood Phase 3 進行中)

- **cache-warden daemon 稼働**: `com.github.kawaz.cache-warden` (launchd、brew .app
  `/Applications/CacheWarden.app/...` + AssociatedBundleIdentifiers、config
  `~/.config/cache-warden/config.toml`、`.cw` socket 3 本 = agent-{kawaz,emerada,syun}.sock.cw)。
  control socket は既定 `$XDG_STATE_HOME/cache-warden/control.sock`。
- **consumer は全部 `.cw` 経由**: `~/.ssh/config` (kawaz/emerada/syun の IdentityAgent)、
  `~/.config/zsh/zshrc` (2 箇所)、`emeradaco/.envrc` (kawaz123 は symlink で同一)、
  `~/.config/git/config-user-emerada.gitconfig` の sshCommand。各所 authsock 行を
  コメントで残してある (戻すならコメント入替)。
- **authsock-warden は canonical socket で稼働継続** (pid 2565、warm fallback)。
- **ロールバック手順**: 各 config のコメントを authsock 側へ戻す
  (`~/.ssh/config.bak-pre-cachewarden-20260613` が switch 前のバックアップ) +
  `cache-warden daemon unregister` (or plist 削除 + bootout) + direnv re-allow。
  本セッションで一度ロールバック→復元しているので手順は実証済み。

## オープンなバグ / 課題

### A. op-refetch loop (要調査・dogfood 再開の主リスク)
離席中に TouchID が ~20 連発。通常起動は op 発見で 1 回だけ (在席で確認)。daemon ログに
`authsock connection error: Broken pipe` 連発。**推定**: 何かが `.cw` agent socket に
繰り返し接続 → SIGN → daemon が op fetch (TouchID) 開始 → クライアントが待たず切断
(broken pipe) → **値が未キャッシュ** → 次接続でまた fetch、の悪循環。
- **要 live 診断**: 在席中に再発したら「何が `.cw` socket に接続しているか」を
  `lsof` / `fs_usage` 等で特定 (前セッションは daemon を止めて live 証拠を失った)。
- **要 fix (cache-warden)**: SIGN 起因の regenerate (op fetch) は要求元クライアントが
  切断しても fetch を完遂して値をキャッシュすべき (一度 fetch すれば以降ヒット = loop
  が self-limiting)。handler/authsock の sign→fetch→cache 順序を確認。

### B. macOS-local CI 失敗 (ECDSA push をブロック)
`cargo test -p cache-warden-cli --test e2e full_lifecycle_over_control_socket` が
**この macOS で決定的に失敗** (e2e.rs:191 "socket should be removed on shutdown")。
- **CI は ubuntu-latest (Linux) で green** = リリース経路は正常、macOS ローカルのみ。
- 今朝 (v0.19.x の `just push`) はローカルでも通っていた。コード不変・ECDSA でも
  parent でも失敗・残骸プロセス無し・リソース正常。
- 手動再現: SIGTERM → プロセス即死だが socket 残存 / SIGINT → graceful shutdown が hang。
  `wait_for_shutdown` は SIGTERM を正しく select している実装。診断 eprintln が
  なぜか出力されない (ping は通る) = **マシン状態起因の疑い** (2 日連続稼働 + 当日の
  大量 daemon churn)。**reboot で解消する可能性**。
- 漏れた socket は DR-0009 stale 検知で次回起動時に除去 = 実害軽微。
- 次セッション: reboot 後に `just ci` を試す or daemon shutdown 応答性 (serve が
  shutdown watch に即応しているか) を実調査。ただし「今朝は通った」ので実バグ断定は慎重に。

### C. 鍵形式の残ギャップ (key-type 監査 `docs/findings/2026-06-13-key-type-signing-matrix.md`)
ECDSA は修正済み。**未対応**: RSA PKCS#1 (`BEGIN RSA PRIVATE KEY`) / FIDO sk-* / 証明書。
DSA は scope 外 (OpenSSH 10 が生成不可)。需要次第で別途。
- `agent-kawaz-rsa.sock` は ssh_config の dangling 参照 (legacy RSA サーバ用、実在せず)。
  RSA 鍵自体は kawaz socket に列挙されるので、対象ホストを agent-kawaz.sock(.cw) に
  向ければ直せるが、全 kawaz 鍵が見えるようになるため kawaz の判断保留中。

### D. hard-ttl=24h の TouchID 頻度
config の SSH 鍵 source は `hard-ttl=24h` = 各鍵 24h ごとに op 再 fetch (TouchID)。
authsock-warden は TTL 未配線=再 fetch なし。dogfood で増える点。長寿命鍵なので
hard-ttl 延長 (例 30d) or 無期限 or prefetch+pin で warm 維持、を kawaz と要相談 (保留)。

## 未実装の確定設計 (DR あり)

- **DR-0018 prefetch 本体 + authsock NS 正規化**: `kv prefetch [KEY...] [--namespace NS]...
  [--defs FILE]... [--all] [--pin DUR]` / 起動時 prefetch (authsock source の
  `prefetch=true`、SoftExpired 封印) / 内部鍵 `__authsock_op:*` を予約 NS `authsock` に
  正規化 (kv.get 拒否)。型付き source/auth スキーマ (DR-0018 §1-3) は実装済み (v0.17.0)。
- **DR-0016 OTP** は実装済み (v0.12.0)。**DR-0013/0014/0015/0017/0019/0020 実装済み**。

## stable-which 連携 (peer セッション、0.4.0 設計協調)

cache-warden は daemon register のバイナリ安定解決に **stable-which 0.3 (crates.io)** を
使用 (`resolve_stable_path(SameBinary)` + `Candidate.path`/`.tags` + `PathTag::
{BuildOutput,Ephemeral}` の matches!)。stable-which が 0.4.0 で durability 第一級
モデル化中:
- API は **`is_stable()` bool + `tags()`** で確定 (reason enum なし)。`is_stable()` の
  意味は「durable-to-pin」= shim/安定 symlink は durable、versioned-managed (Cellar) は
  not-durable。
- **cache-warden の TODO (0.4.0 移行時)**: `is_unstable_resolution` を `is_stable()`
  経由に書き換え。現状の自前判定は versioned-managed を見落としている潜在バグがあり、
  移行で同時に埋まる。移行案内は stable-which 側 (DR-016 durability 確定後) から来る。
- 連携は cmux-msg (peer session `b9b99f3c-...`) で実施。subscribe を張っておくこと。

## リリース実績 (前 handoff〜本セッション)

v0.8.1 (core dump) → v0.8.2 (定義レジストリ+help 階層) → v0.9.0 (kv define) →
v0.10.0 (--defs+永続化) → v0.11.0 (run/inject/dry-run) → v0.12.0 (OTP) →
v0.13.0 (key 層 allowed_processes) → v0.14.0 (anti-debug ptrace) →
v0.15.0 (positional set+`--`) → v0.16.0 (namespace) → v0.16.1 (永続化 dotted) →
v0.16.2 (op fetch JSON 修正) → v0.17.0 (型付き source/auth) → v0.18.0/v0.18.1
(macOS 署名/notarize + Homebrew Cask 配布開始) → v0.19.0 (stable-which 安定パス解決) →
v0.19.1 (stable-which crates.io 化)。ECDSA は `be30fea4` でローカルコミット済み・未 push。

## 運用作法 (継続)

- push は `just push` (直接禁止)。crates/ 触ったら `just bump-version`。push 後 gh-monitor
  で CI watch、release.yml green で `just on-success-release` (brew 自動 upgrade) が発火。
- 実装はサブエージェント委譲、メインは設計・監査・統合。署名/暗号コードは Opus サブで TDD。
- macOS 署名 skill: `claude-rules-personal/for-me/skills/macos-signing-notarization/`。

## 関連
- [DR INDEX](../decisions/INDEX.md) (DR-0013〜0020)
- [docs/findings/2026-06-13-key-type-signing-matrix.md](../findings/2026-06-13-key-type-signing-matrix.md)
- [2026-06-12-parity-phase2.md](./2026-06-12-parity-phase2.md) (Phase 2 検証)
