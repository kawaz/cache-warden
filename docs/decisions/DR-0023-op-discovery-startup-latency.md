# DR-0023: 起動時 op discovery のブロッキングを解消 (blocking pool 化 + lazy refresh)

- Status: Accepted (Phase 1) / Proposed (Phase 2) (2026-06-14)
- Related: DR-0018 (型付き source、prefetch / `force_eager`) / DR-0021 (signal / shutdown、startup 中シグナル取りこぼし防止の前提) / DR-0008 (単一 daemon、tokio runtime) / 関連 issue `docs/issue/2026-06-14-ssh-agent-provider-architecture.md` (Provider 再設計の動機)

## Context

dogfood Phase 3 中、DR-0021 のシグナル設計調査で **`daemon run` の startup 中に SIGINT/SIGTERM が pending のまま消費されない** ことを sample スタックで確認した (起点は `docs/issue/2026-06-13-op-discovery-blocks-startup.md`)。

コード調査 (2026-06-14) で原因を確定:

```
daemon_cmd.rs:67  tokio::block_on()
  └─ server::run()                       [server.rs:182, async]
      ├─ bind_control_socket()           [行 221, sync 軽量]
      ├─ register_definitions()          [行 245, sync, eager preload]
      └─ spawn_listeners()               [行 317, sync 関数]
          └─ discover_all_sources()      [authsock.rs:144]
              └─ for source in sources:
                  └─ discover_keys(...)  [op_discovery.rs:61, sync]
                      ├─ client.item_list_json(...)        [op_discovery.rs:77]
                      │   └─ RealOpClient::run()           [op.rs:159]
                      │       └─ Command::output()         [op.rs:160 ★ std::process、同期 spawn+wait]
                      └─ client.item_get_public_key_json(...) [op_discovery.rs:115、キャッシュ未ヒット時に再ブロック]
  ★ ここを抜けないと wait_for_shutdown(...) [server.rs:326] の await に到達できない
```

- `discover_keys` / `RealOpClient::item_list_json` / `item_get_public_key_json` は **すべて sync**
- 内部で `std::process::Command::output()` を直接呼び、`tokio::process::Command` でも `tokio::task::spawn_blocking` でもない
- `spawn_listeners()` 自体が sync 関数なので、`run()` は同関数完了まで `wait_for_shutdown()` の await 地点に到達できない
- DR-0021 で「startup 中のシグナル取りこぼし防止」のため `cw-signal` スレッドが `Notify` で permit を保持しているが、**`notified().await` に到達するまで permit は滞留したまま**

= startup latency が **op CLI の所要時間に律速** され、ネット遅延 / TouchID 待ち / `op` ハングがあれば最大 `SHUTDOWN_GRACE` (5s) まで停止応答性が落ちる。watchdog (DR-0021) があるので「停止不能」にはならないが応答性問題は残る。

DR-0018 では「公開鍵 index は常駐、秘密鍵は lazy」を方針として確立済み、現コードもこの方針自体は満たしているが、**「常駐」の手段が同期ブロッキング** という乖離が今回の発見。

## Decision

2 phase で段階的に解決する。

### Phase 1: `spawn_listeners` を `tokio::task::spawn_blocking` に包む (近期、本 DR 採択)

`spawn_listeners()` の呼び出しを `tokio::task::spawn_blocking(|| spawn_listeners(...))` でラップ、結果を await。

- main runtime worker は **ブロックされず**、`select!` で blocking task 完了と shutdown signal を並行 await できる
- startup 中の SIGINT/SIGTERM は `wait_for_shutdown` 経路 (`Notify`) に到達可能になり、即応する
- `spawn_blocking` が走る blocking pool は tokio default (512 workers)、startup は 1 task のみ消費なので枯渇しない
- shutdown signal が startup 中に来た場合の挙動:
  - `select!` 側で shutdown を観測 → blocking task は **abort できない** (= std::process が回っている)
  - watchdog (DR-0021) が 5 秒後に `_exit(0)` するので bounded-exit は保証 (watchdog の存在意義がここで活きる)
  - = blocking pool に乗せても abort 不能性は変わらないが、**main runtime の応答性 (= shutdown 信号の認識)** は回復する

### Phase 2: `discover_keys` 自体を lazy + background refresh に (将来、別 DR 化候補)

- 起動時の eager discovery を廃止し、最初の SIGN_REQUEST まで discovery を遅延 (= cold path はそこで負担)
- 並行で background refresh task が定期的に op discovery を回し、warm cache を維持
- warm 状態では SIGN_REQUEST の overhead は zero
- DR-0018 の `force_eager` (= authsock keys は startup eager) は **公開鍵 index** のみ eager に整理 (= 秘密鍵 lazy と分離)
- `docs/issue/2026-06-14-ssh-agent-provider-architecture.md` の Provider 再設計と整合する構造 (Provider 抽象化と一体で実装すれば自然)
- Phase 2 単独実装は **Provider 再設計と被るので、Provider 再設計が動くまで保留** (= 二重作業を避ける)

## Alternatives Considered

### 案 A: `discover_keys` を `tokio::spawn` で detach、startup 即完了

- startup が即時完了、socket は ready 状態
- ⚠️ detach 中の初回 SIGN_REQUEST は discovery 未完了で `NotLoaded` を見て `agent refused` を返す → ssh client が「鍵不在」と判断して別経路を試行 or exit
- ⚠️ socket ready なのに「鍵が空っぽ」は期待値と乖離 (= 「daemon ready の意味は何か」が曖昧になる)
- ❌ Phase 1 では不採用 (= 体感悪化、Phase 2 で lazy 化する際は discovery 完了前の socket close 等で対応)

### 案 B: `discover_keys` に timeout を設け、超過なら lazy fallback

- 最大 startup latency を制御 (e.g. 3 秒)
- ⚠️ timeout が乗っているだけで、startup を 0 にはできない (3 秒は依然 startup blocking)
- ⚠️ lazy fallback の状態遷移を新規追加するので Phase 2 と機能が被る
- ❌ Phase 2 への中途半端な近似なので不採用 (= Phase 1 で blocking pool 化 → Phase 2 で完全 lazy 化、の階段が筋良い)

### 案 C: server.rs と authsock listener を別プロセス化

- 本質的に decoupled、startup blocking は authsock prosess 側に閉じる
- ⚠️ DR-0008 (単一 daemon、秘密値の 1 プロセス閉じ込め) を覆す
- ❌ 不採用 (= 秘密値が IPC を渡る = mlock / zeroize 境界が崩壊、DR-0008 の根幹を否定)

### 案 D: 何もしない (= watchdog に任せる)

- ⚠️ DR-0021 watchdog で「停止不能」は防げているが、応答性問題は残る
- ⚠️ startup hang 状態の daemon を `launchctl kickstart -k` 等で叩く運用負担が dogfood で残る
- ❌ 不採用 (= 設計上の弱点を rule 化して受け入れるのは design-priority.md に反する)

## Why blocking pool が筋良い (= 設計の正しさ)

- `Command::output()` (std::process 同期) は **構造的に blocking**、async 化するには `tokio::process::Command` への置き換えが必要だが、そこは認証経由 (= `op` の TouchID プロンプトを含む) で別 issue (touchid-blocks-blocking-pool) と整合させる必要があり、本 DR の範囲外
- blocking pool 化は **既存の同期 API を保ったまま** runtime 応答性を回復する最小侵襲解
- 「op CLI を sync で呼ぶ」前提は今後も残るので (= async op CLI library を新規追加せず CLI shell-out で済ます DR-0004 / DR-0014 方針)、blocking pool 化が長期的にも妥当な配置
- 同じ理由で `register_definitions` の eager preload (= 同じく sync の op CLI 実行) も同じ blocking pool 化が筋良い (= 本 DR の範囲、Phase 1 と一緒に対応)

## Trade-off (Phase 1)

| 観点 | 評価 |
|---|---|
| startup 応答性 | 改善 (= main runtime worker がブロックされない、shutdown signal 即応) |
| startup 完了時間 | 不変 (= blocking pool でも op CLI の実時間は同じ) |
| 体感 (= 起動直後の SIGN_REQUEST) | 不変 (= startup 完了まで authsock socket は bind 完了していないので connect refused、これは現状と同じ) |
| abort 可否 | 不変 (= std::process は abort 不能、watchdog で bounded-exit) |
| 実装侵襲度 | 小 (`spawn_listeners` 呼び出しを `spawn_blocking` でラップ + `select!` 追加) |
| 既存テストへの影響 | 影響範囲は startup path のみ、e2e は引き続き通るはず (要検証) |

## Implementation Notes (Phase 1)

### 1. `spawn_listeners` の呼び出し変更

`crates/cache-warden-cli/src/daemon/server.rs` の `run()` 内で:

```rust
// Before
spawn_listeners(&mut tasks, ...)?;

// After
let listeners_result = tokio::select! {
    res = tokio::task::spawn_blocking(move || {
        // 既存 spawn_listeners のロジックを move
    }) => res,
    _ = shutdown_notify.notified() => {
        // startup 中に shutdown signal が来た
        return Err(ServerError::ShutdownDuringStartup);
    }
};
let _tasks = listeners_result.map_err(...)?;
```

- `spawn_listeners` が `&mut tasks` を取る場合、closure 内で完結する形に refactor が必要 (= TaskTracker を closure 内で構築して `await` 側で main tracker に merge)
- `register_definitions` の eager preload も同じ pattern を適用

### 2. shutdown signal during startup

- DR-0021 で startup 中の signal 取りこぼしは Notify permit で防げている
- 本 DR の `select!` 追加で **startup 中の signal が即応されて Err 返却** される経路ができる
- main の `daemon_cmd::run_foreground` 側で `ShutdownDuringStartup` を recoverable に扱い、socket cleanup + exit 0 (= 意図的 shutdown)

### 3. テスト (TDD)

- **既存 e2e の `full_lifecycle_over_control_socket` が引き続き green** (= 通常 startup → shutdown が回帰しない)
- 新規テスト: **fake op が 30 秒スリープを返す条件で** `cache-warden daemon run` を spawn、開始から 1 秒以内に SIGTERM を送り、**5 秒以内に exit** することを確認 (= startup hang 中の shutdown 応答性)
- fake op は既存の e2e で使われている mock の延長

### 4. ログ追加

- `spawn_blocking` task 開始時に `cache-warden: discovering op-backed keys ...` を stderr に 1 行
- 完了時に `cache-warden: discovery completed in <duration> (<n> sources, <m> keys)` を 1 行
- = startup hang の可視化 (kawaz が「何で待っているか」がログから即わかる)

## Open Questions (Phase 2 用)

- **Q1**: Phase 2 (`discover_keys` を lazy + background refresh) は **Provider 再設計と一体化** で進めるべきか、独立して先行するか
  - Provider 再設計 (`docs/issue/2026-06-14-ssh-agent-provider-architecture.md`) は idea 段階、DR 化前
  - Phase 1 で応答性問題は十分緩和されるので、Phase 2 は Provider 再設計の DR 化を待つ判断
- **Q2**: `register_definitions` の eager preload (= `[kv.*].preload = true` で起動時 fetch する KV エントリ) も同じ blocking pool 化を本 DR で扱うか
  - **本 DR で同時対応**: 同じ「sync op CLI を startup で叩く」構造、一緒に直すのが筋
- **Q3**: blocking pool に乗せた task が `Command::output()` でハングした場合、`spawn_blocking` の handle を `abort` しても std::process は止まらない (= macOS の prctl 系がない、子プロセス kill が別途必要)
  - 本 DR では handle abort は試みず、watchdog (DR-0021) に bounded-exit を委ねる
  - 子プロセス kill を入れるなら `tokio::process::Command` への移行が筋良い (= Phase 2 で検討)

## Related

- `crates/cache-warden-cli/src/daemon/server.rs:182-326` — `run()` (本 DR の修正対象)
- `crates/cache-warden-cli/src/daemon/authsock.rs:144` — `discover_all_sources`
- `crates/cache-warden-authsock/src/op_discovery.rs:61-115` — `discover_keys`
- `crates/cache-warden-authsock/src/op.rs:159-226` — `RealOpClient::run` / `item_list_json` / `item_get_public_key_json`
- `docs/issue/2026-06-13-op-discovery-blocks-startup.md` — 起票元 issue
- `docs/issue/2026-06-14-ssh-agent-provider-architecture.md` — Phase 2 と一体化候補
- `docs/issue/2026-06-14-touchid-blocks-blocking-pool.md` — 関連副次問題 (TouchID 中 Mutex 保持)
- DR-0018 — `force_eager` / 公開鍵 index 方針
- DR-0021 — signal / watchdog (= 本 DR が watchdog の存在価値を改めて利用)
