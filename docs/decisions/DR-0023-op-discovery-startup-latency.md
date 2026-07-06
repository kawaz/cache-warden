# DR-0023: 起動時 op discovery のブロッキングを解消 (blocking pool 化 + lazy refresh)

- Status: Accepted (Phase 1 2026-06-14; Phase 2 2026-07-06)
- Related: DR-0018 (型付き source、prefetch / `force_eager`) / DR-0021 (signal / shutdown、startup 中シグナル取りこぼし防止の前提) / DR-0008 (単一 daemon、tokio runtime) / DR-0026 (discovery 失敗時 disk-cache fallback。Phase 2 の registry seed はこの cache→`DiscoveredKey` 変換を再利用) / DR-0022 (per-key fetch backoff。Phase 2 の task-level retry backoff とは別レイヤ) / 関連 issue `docs/issue/2026-06-14-ssh-agent-provider-architecture.md` (Provider 再設計の動機)

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

### Phase 2: listener 即時 bind + disk-cache seed + background discovery (採択、2026-07-06)

P1 (= `spawn_listeners` が discovery 完了を await するため、op hang 時に listener
起動が最大 30s 遅延、最悪 launchd context では永久に bind されない) を解消する。

**当初の Phase 2 案 (= 初回 SIGN_REQUEST まで discovery を遅延) は採らない**。
「socket ready なのに鍵が空」問題 (案 A の弱点) を避けつつ、DR-0026 で
**disk-cache から public key を復元する変換が既に存在**するので、それを起動時 seed
に転用する方が筋が良い (= 二重作業を避ける、Provider 再設計を待たずに独立実装可能)。

採択した構造:

1. **listener 即時 bind**: `run()` は discovery 完了を待たず `spawn_listeners` する。
   初期 registry は disk cache からの seed (`seed_all_sources_from_cache` →
   `seed_from_cache` = DR-0026 `fallback_from_cache` と**同一変換・同一境界規則**
   = provenance / vault / item filter)。cold first-start は seed 空で bind (= それでも
   「listener 不在」より改善)。**公開鍵 index の常駐手段が「同期 op ブロック」から
   「disk-cache seed」に変わっただけ**で、秘密鍵 lazy fetch (DR-0018 / DR-0014) は不変。
2. **background discovery (source 単位 apply)**: 起動後に `op_discovery_refresh` task が
   blocking pool で `discover_all_sources` を回し、live enumerate に成功した source を
   **その source ごとに即 hot-swap** する (`SourceDiscovery.fresh` = live 成功した source
   名の集合)。既存 `spawn_github_refresh` と同じ「blocking pool 上で外部 CLI を回して
   共有状態を更新」パターンに揃えた。**全 source 一括 (`all_fresh`) ではなく source 単位**
   なのは、恒久的に到達不能な source (未 sign-in の別アカウント等) が 1 つでもあると、
   健全な source の live key が永久に適用されず (cold cache では 0 key serving)、retry
   loop も終わらない all-or-nothing 退行を避けるため。apply は blocking pool 上で行う
   (`apply_discovery` は store lock + registry write を取り、並行 sign が `op item get`
   / TouchID 中に store lock を保持しうる = async worker を塞いではならない、DR-0008)。
3. **registry 共有可変化**: `SocketState.registry` を `Arc<RwLock<PublicKeyRegistry>>`
   に。hot path (REQUEST_IDENTITIES / SIGN) は read guard を短命に取り、refresh は
   write guard で swap のみ。rebuild は **immutable な local base (config `keys` の
   公開鍵) を clone + fresh op keys** で組む (= local key は core を再読しないので TTL
   失効で消えない)。**lock 順序**: `local_sign` は registry read guard を **鍵解決だけに
   限定** (blob → KV key を clone したら drop、その後の auth gate / op fetch には持ち込ま
   ない) = queue した `apply_discovery` の write guard が新規 reader を塞がない (std
   `RwLock` は writer 優先で、read を長く持つと待機 writer が後続 read を止める)。
   `apply_discovery` は store lock (def 登録) と registry write を**同時に持たない**ので
   inversion もしない。
4. **失敗時 retry (source 単位 task-level backoff)**: 未解決 source が残る間は
   task-level exponential backoff (2s→…→60s cap) で retry。**各 source は解決した瞬間に
   apply され、以降その source は再 discovery しない** (= 解決済み source の `op item list`
   を無駄に再実行せず、biometric session を無用に温め続けない)。**全 target source が live
   になったら loop 終了**、以降は既存 lazy fetch 経路に委ねる (= 解決済み source の周期的
   自動再 discovery は新設しない、投機的 config option も足さない)。DR-0022 の per-key
   fetch backoff とは別レイヤ。全 wait (discovery / apply / backoff) は shutdown channel と
   select 可能 (= Phase 1 の応答性を踏襲、discovery hang 中でも SIGTERM 即応)。
5. **multi-source cache 永続化 (clobber 回避)**: `discover_all_sources` は各 source の
   fresh cache を per-source `save()` で書くのではなく、disk cache を 1 度 load して
   **merge (`merge_source_cache`: 当該 source の旧 entry を provenance + vault/item 境界で
   置換、他 source の entry は温存) → 末尾で 1 度 save**。per-source save は共有
   `op_map.json` を最後の source の鍵だけに全置換 clobber し、Phase 2 が seed 元にする
   disk cache から兄弟 source の鍵を消してしまうため。single-source では従来 save と同一結果。
6. **shutdown 応答性**: seed bind + background 化で startup が op に律速されなくなった
   ため、`run()` は discovery で `ShutdownDuringStartup` を返さなくなった (= startup
   block 自体が無い)。background task は `handles` に積んで shutdown で await する
   (github refresh task と同じ扱い)。

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

## Resolved Questions

- **Q1** (Phase 2 は Provider 再設計と一体か独立か): **独立して先行**で解決。DR-0026 の
  cache→`DiscoveredKey` 変換を seed に転用でき、Provider 再設計 (idea 段階) を待つ必要が
  なかった。Provider 再設計が入る際は seed / background 経路をその抽象に載せ替えればよい。
- **Q2** (`register_definitions` eager preload も blocking pool 化するか): Phase 1 で
  **同時対応済み**。
- **Q3** (`spawn_blocking` の op がハングしたら handle abort では止まらない): Phase 2 でも
  同じ判断。background discovery task は shutdown で select 抜けするが、`spawn_blocking`
  上の `op` 子プロセスは detach したまま残り、process exit で刈られる (watchdog / OS)。
  子プロセス kill が要るなら `tokio::process::Command` 移行が筋 (= 将来の別作業)。

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
