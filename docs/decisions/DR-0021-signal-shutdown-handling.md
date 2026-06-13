# DR-0021: シグナルベースの shutdown 処理 (sigwait + watchdog)

- Status: Active
- Date: 2026-06-13

## Context

デーモン (`daemon run`) は SIGINT / SIGTERM を受けて graceful shutdown
(accept ループ停止 → 各 socket ファイル unlink) する。当初は tokio の非同期
シグナル driver (`tokio::signal::ctrl_c` / `signal(SignalKind::terminate())`) で
受けていた。

**実機で確定したバグ (制御実験で因果を特定)**: macOS の anti-debug hardening
`ptrace(PT_DENY_ATTACH)` (DR-0007 の防御層、`hardening::deny_debugger_attach`) が
**tokio の非同期シグナル driver を壊す**。`[daemon].allow-debug-attach` トグル
だけで挙動が反転することを確認した:

| hardening | tokio::signal の挙動 |
|---|---|
| ON (デフォルト) + signal 登録が ptrace の後 | SIGTERM が catch されず kernel default disposition で即死 (exit 143)、control socket 残存 |
| ON + signal 登録が ptrace の前 | catch はされるが self-pipe→kqueue 配送が racy で hang |
| OFF | 常に正常 |

Linux は hardening に `prctl(PR_SET_DUMPABLE)` を使い、これはシグナルに影響しない
(CI = Linux は緑、macOS ローカルのみ `full_lifecycle_over_control_socket` e2e が
失敗、という症状に一致)。

非同期 driver が PT_DENY_ATTACH 下で信頼できない以上、driver に依存しない経路が要る。

## Decision

### 1. シグナルをプロセス全スレッドでブロックし `sigwait` で同期受信

- `block_shutdown_signals()`: SIGINT/SIGTERM を `pthread_sigmask(SIG_BLOCK)` で
  ブロック。**tokio runtime build の前** (`daemon_cmd::run_foreground`) に呼ぶ
  → 全 worker スレッドがマスクを継承。`Builder::on_thread_start` でも各 worker で
  明示ブロック (継承仕様が変わっても穴が開かない belt-and-suspenders)。
- 専用 std スレッド (`cw-signal`) で `sigwait()` を回す = **kqueue driver を完全
  バイパスする同期 kernel call**。PT_DENY_ATTACH の影響を受けない。
- 受信したら `tokio::sync::Notify::notify_one()` で async 側を起こす。`run()` は
  startup 後に `notified().await`。`Notify` は permit を 1 つ保持するので、
  **startup 中に来たシグナルも取りこぼさない** (スレッドは startup より前に spawn)。

### 2. shutdown watchdog (bounded-exit 保証)

全シグナルをブロックした結果、「SIGTERM で OS が即 terminate する」という安全網が
消える。高負荷で `run()` が starve して graceful shutdown を駆動できないと永久に
終了できなくなりうる。これを防ぐため `cw-signal` スレッドは notify 後に
`SHUTDOWN_GRACE` (5s) 待ち、まだプロセスが生きていれば control socket を unlink して
`libc::_exit(0)` する。graceful shutdown が先に完了すればプロセスごと消えるので
watchdog コードには到達しない (正常時の shutdown は実測 ~24ms、watchdog 非発火)。

- `_exit` は `SecretBytes` の Drop (zeroization) を skip するが、mlock (DR-0007) +
  `RLIMIT_CORE=0` で秘密はディスクに出ず、プロセス終了で RAM は OS が回収する。
  これは SIGKILL / クラッシュと同等で DR-0007 の脅威モデル (ディスク漏洩対策) の
  範囲外。
- authsock socket は watchdog 経路では unlink せず、次回起動の stale 検知 (DR-0009)
  に委ねる (watchdog は早期 spawn のため authsock パスをまだ知らない)。
- exit code は 0: SIGINT/SIGTERM 起因の停止は意図的 shutdown なので成功扱い
  (可観測性は強制 exit 時の stderr 警告で確保)。

### 3. 子プロセスはクリーンな signal mask で起動

signal mask は `fork` も `exec` も跨いで継承される。プロセス全体ブロックの副作用で、
デーモンが spawn する子 (source command / 再認証 command / `op` CLI) が
**ブロック済み SIGINT/SIGTERM を継承し killable でなくなる** regression が生じる。
`cache_warden::spawn_with_clean_signal_mask()` (`CommandExt::pre_exec` で子の
マスクを空に reset) を全 spawn 箇所に適用して防ぐ。

### 4. fallback

`cw-signal` スレッドの spawn に失敗 (ほぼ不可能) した場合、シグナルはブロック済み
かつ consumer が居ない = 停止不能になる。この縮退経路では signal を**アンブロック**
して OS default disposition (terminate) に戻す。tokio の `ctrl_c` には**戻さない**
(壊れている driver 経由になり、しかも SIGINT handler を入れると default kill すら
無効化されるため)。

## Alternatives considered

- **tokio::signal を使い続ける** — PT_DENY_ATTACH 下で配送が壊れる (本 DR の発端)。却下。
- **macOS で PT_DENY_ATTACH を撤去** — シグナル問題は消えるが DR-0007 の hardening 層を
  弱める。脅威モデルを下げる判断は不採用。
- **graceful shutdown を `tokio::time::timeout` で包む** — startup starvation には効かない
  (runtime が駆動されなければ timeout も発火しない)。watchdog を std スレッド側に置く
  必要があり、async timeout は代替にならない。
- **`std::process::exit` (watchdog)** — destructor を走らせない点は `_exit` と同じだが、
  wedged 状態での確実な終了性は `_exit` の方が強い。`_exit` を採用。
- **子の mask 継承を放置** — `kill -TERM <child>` が効かない / orphan が残る実害
  (Codex レビューで確認)。spawn 時 reset を採用。

## 関連

- DR-0007 — mlock / 秘密値のメモリ保護。`PT_DENY_ATTACH` はこの hardening 層の一部。
- DR-0008 — 単一 tokio デーモン。本 DR はその shutdown 経路の確定。
- DR-0009 — control socket の stale 検知。watchdog 強制 exit 時の authsock socket
  cleanup はこれに委ねる。
