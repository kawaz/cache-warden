# launchd-context での cw discovery 永久 block 事故 (dogfood)

- Date: 2026-06-17
- 関連 issue: [2026-06-13-op-discovery-blocks-startup](../issue/2026-06-13-op-discovery-blocks-startup.md) / [2026-06-14-ssh-agent-provider-architecture](../issue/2026-06-14-ssh-agent-provider-architecture.md) / [2026-06-14-touchid-blocks-blocking-pool](../issue/2026-06-14-touchid-blocks-blocking-pool.md)

## サマリ

cache-warden daemon は launchd 経由起動だと **discovery で永久 hang して listener を一切開始しない**、結果 `agent-{kawaz,emerada,syun}.sock.cw` への connect 全死 → push/commit signing が「No such file or directory」で失敗、という事故が朝以降発生。並走している authsock-warden は **同じ launchd context** で平気に動いていた。両者の構造差を実証で詰めた記録。

## 時系列

- **朝起床時**: ロック解除直後に 1Password の TouchID プロンプトが大量噴出して止まらず、対応として **1Password を全終了**。`op item get` が呼ばれてた cache-warden 子プロセス + authsock-warden 子プロセスが in-flight のまま親プロセスの socket を失い宙ぶらりんに。
- **作業再開時** (14:00 頃): emerada リポで `git commit` / `git push` が永遠に返らない。`ssh -vvv` で `get_agent_identities: ssh_get_authentication_socket: No such file or directory`。
- **1Password 再起動**: 直後にアプリ側がアップデート再起動 (`--just-updated --should-restart`)。古い op 子プロセスは旧アプリの socket を握ったまま FOR HOURS 残置 (= timeout なし)。
- **症状切り分け**: ターミナルから直接 `op item get` を叩くと 20s 程度で成功 (TouchID 経路活きてる)。一方 cache-warden daemon 子の `op item get` (PID 87650-ish の連鎖) は応答ゼロのまま。
- **真因切り分け実証**: launchd 起動の cache-warden daemon を bootout、**terminal foreground で同じバイナリを起動**したところ discovery が **4.35s で成功 (6 keys)** し 3 socket すべて listen 開始。同じバイナリ・同じ config・同じ 1Password app に対して **起動 context が違うだけで挙動が真逆**になった。

## 構造差の実証 (kawaz/authsock-warden 旧コード再読)

旧 authsock-warden (= `cache-warden-authsock` crate に absorb された前身) の `src/agent/warden_proxy.rs` を読み直して、当初の自分の推測 ("authsock は proxy だから速い") が誤りだったことを訂正:

| 項目 | 旧 authsock-warden | 現 cache-warden |
|---|---|---|
| discovery タイミング | **lazy** (`ensure_op_initialized()` line 524-580、初回 REQUEST_IDENTITIES で trigger) | **eager** (`cache-warden-cli/src/daemon/server.rs:466-509` で起動時 await) |
| op discovery 失敗時 | `OpState::Failed { error, failed_at }` で印、60s 経過後リトライ。listener は生きてる | `discover_all_sources` が completion を返さないので `spawn_listeners` (line 512) 到達せず、socket が一つも作られない |
| 鍵列挙の primary path | **1Password agent socket** (`refresh_op_keys_from_agent()` line 781-、TouchID 不要) + `OpKeyCache` fingerprint 突合 | op CLI `item list` のみ |
| launchd context (op CLI が biometric 取れない時) の挙動 | 旧 disk cache + agent socket 経路で identities 出せる → 通常運用継続 | 起動 discovery で永久 block、listener 開始ゼロ → クライアントは ENOENT |

実証用ログ:
- 旧 authsock-warden の SIGN_REQUEST は receive→success が **sub-ms**: 04:25:03.827057 → 04:25:03.827380 = 323µs (`~/Library/Logs/authsock-warden/output.log`)。op CLI 呼ぶならこの速度は出ない = キャッシュ済 PEM のローカル署名。"proxy で速い" は誤読。
- cache-warden の `daemon.log` discovery 完了時間: 起動時 8.50s → 1Password 不調時 272.21s → 今回の事故時 ∞ (kill するまで戻らず)。

## 既存 issue との対応関係

3 つの open issue がたまたま重なって今回の致命症状を引き起こした:

1. **[2026-06-13-op-discovery-blocks-startup](../issue/2026-06-13-op-discovery-blocks-startup.md)**: 真因の本丸。ただし当時の「影響」セクションは `DR-0021 watchdog で最終的に殺されるので停止不能にはならない` という停止応答性の話に矮小化されていた。今回の観測でわかったのは「**watchdog は起動完了後の SIGTERM に対する保険であって、起動中の永久 block を救わない**」「listener が立たない結果 client が ENOENT で失敗する」という運用上の致命症状で、issue 側に追記すべき。
2. **[2026-06-14-ssh-agent-provider-architecture](../issue/2026-06-14-ssh-agent-provider-architecture.md)**: idea 段階の大規模再設計、`UpstreamAgent Provider` (= 旧 authsock-warden の `refresh_op_keys_from_agent` 相当) を含む。「pubkey 列挙と秘密鍵 fetch の分離 — op-discovery-blocks-startup の解」と明記済み (line 93)。今回の事故はこの大設計を land するまでの interim period に発火した。
3. **[2026-06-14-touchid-blocks-blocking-pool](../issue/2026-06-14-touchid-blocks-blocking-pool.md)**: 今回の主因ではないが、同じ root cause カテゴリ (= op CLI 同期実行が daemon 応答性を奪う)。

## 取った手当て

事故対応:
- 詰まっていた op 子プロセス chain を kill して daemon を unblock
- 全 SSH agent socket を symlink 構造に再編 (= `~/.ssh/agent-<name>.sock` を `.sock.cw` / `.sock.aw` 切替の symlink、両 daemon は別 path で並走 listen)。client config を `.sock` 1 本に簡素化、切替は `ln -sfn` 手動
- emerada は authsock-warden 経路で再開 (= 仕事リポなので業務停止を最短で解消)
- 残り (kawaz/syun) は authsock-warden 経路に flip して暫定回避

構造修正:
- `op` CLI 子プロセスに wall-clock timeout を被せる ([Task #2 で TDD 実装、本 commit 内](#))。これだけでは「永久 hang を防いで失敗扱いにする」までで discovery 自体は治らないが、後続の lazy 化 / agent socket fast path の前提として要る (= 失敗を "失敗" と認識できる土台)

## 学び / 派生

- 「私 (= Claude) が `authsock-warden は signing を proxy する設計` と推測 → kawaz に "コード把握しろよ" と怒られて訂正」という痛みがあった。**proxy ではなく value cache + 1Password agent socket からの identity 列挙**が真実。記録残しておかないと同種の誤読を kawaz / 別 session で繰り返す危険がある (= 本 journal の目的の一つ)
- launchd context での op CLI 制約は **op CLI バイナリ側の挙動** (= biometric チャネルが GUI session 必須) で、cache-warden コードでは直接いじれない。**1Password agent socket 経路を持つこと** が回避策の本筋 (= ssh-agent-provider-architecture が描いている方向で正しい)
- TouchID 大量噴出 → ユーザが force-quit する、というシナリオは 1Password 利用者にはありふれているはず。「discovery が永久 hang する」「forced quit から復旧してもプロセスツリーに古い op が残る」は、TouchID 噴出問題が解決されるまでは何度でも再発する class の事故

## 関連 commit

- 本 journal と同 PR: op CLI 子プロセスに wall-clock timeout (`crates/cache-warden-authsock/src/op.rs`)
