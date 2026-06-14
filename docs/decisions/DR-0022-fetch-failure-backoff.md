# DR-0022: 秘密値 fetch 失敗時の short-term backoff (negative cache)

- Status: Accepted (2026-06-14 起票 → 同日 Codex review v1 反映 → 同日 Codex review v2 反映)
- Related: DR-0014 (entries / definitions 分離、本 DR の状態管理位置決めの前提) / DR-0011 (TTL 2 分離 = lifecycle 概念、本 DR は別カテゴリ retry policy) / DR-0018 (型付き source、prefetch) / DR-0021 (signal / shutdown)

## Status note: 2026-06-14 改訂 (v1 → v2 = 2 ラウンドの Codex review)

### v2 改訂 (2 ラウンド目反映、本セクション直下)

v1 改訂版に対する Codex re-review で以下が追加指摘され v2 で反映:

| 重大度 | 指摘 | v2 改訂対応 |
|---|---|---|
| Critical | `Store::set` で `failure_backoffs` を削除する仕様は、adapter 経由の static 値投入 (`kv.set`) でも走り、Store の契約に意図しない副作用を持ち込む | **`failure_backoffs` の操作は `regenerate` / `get_or_regenerate` 経路だけ**に閉じ込め、`Store::set` からは触らない設計に変更 |
| Critical | A-3a 「lazy_load_op_key を core 経由統一」を**前提条件**に格上げした結果、A-3a が遅延すると本 DR の core backoff が authsock handler に到達せず「core 一本化」が嘘になる期間ができる | A-3a を **separate PR** として独立宣言し、Consequences に scope (file 単位 + 期待 SLOC) を明示。**adapter 側暫定 backoff は不採用**を再確認 (= 構造を綺麗に保つ、A-3a 完了まで dogfood は他の手段で凌ぐ) |
| Warning | `failure_backoffs` の process restart 揮発が continuous restart loop attack (= systemd restart で backoff を毎回 reset) に無防備 | **within-session 限定**を明示、restart loop attack は cache-warden の脅威モデル外 (= systemd / launchd の責務) と整理。case W1c 採用 |
| Warning | `Store::new()` vs `Store::with_failure_backoff` の migration path 曖昧 | `Store::new()` は維持、`Store::set_failure_backoff(Duration)` setter を追加。library consumer は default `Duration::ZERO` = backoff 機能なしのまま、daemon だけが setter 経由で config から有効化 |
| Warning | `failure_backoffs` の削除タイミング (kv.del / hard-ttl) が非対称、ミスリード | **`failure_backoffs` の lifetime は `definitions` の lifetime と一致**に統一。`kv.del --with-define` で削除、`kv.del` (値のみ) は残す、hard-ttl 切れも残す (= 定義がある限り failure 履歴は意味がある) |
| Warning | SSH agent protocol に "retry later" 機構がなく `agent refused` 一択、ssh client 側の retry 動作頼み | OpenSSH client の `ConnectionAttempts` / ssh-retry 系外部ツール頼みを明記、agent protocol 拡張は scope 外として確定 |
| Info | `Store::with_clock` テスト fixture と authsock.rs 既存テストの相互参照が曖昧 | Implementation Notes に「authsock.rs 既存テストの with_clock fixture 改修」を明示 |
| Info | 可観測性 stderr の emit 位置が曖昧 | file:line を明示 (`crates/cache-warden-cli/src/daemon/authsock.rs:920` 周辺の failed sign log) |

### v1 改訂 (1 ラウンド目反映、以下は履歴)

初版 (2026-06-14 起票) は `last_failure_at: Option<Instant>` を `Entry` に持たせる案だったが、Codex adversarial review で以下の根本問題が指摘され改訂した:

| 重大度 | 指摘 | 改訂対応 |
|---|---|---|
| Critical | `last_failure_at` の置き場が無い (DR-0014 で `Store::entries` は definition-only を持たない、初回 lazy 失敗時 entry が物理的に存在しない) | 別フィールド `failure_backoffs: BTreeMap<String, FailureRecord>` に変更 |
| Critical | 「authsock 側暫定重複」は core 一本化と矛盾 | 「先に `lazy_load_op_key` を core API 経由に統一する」を**前提条件**に明示 |
| Warning | TTL/pin と「同列の lifecycle 概念」は誤分類 | 分類を「source 実行の retry policy / circuit breaker」に変更 |
| Warning | 公開 API 変更 (`RegenerateOutcome::Backoff` / `RegenerateDefOutcome`) の library consumer 影響評価ゼロ | Consequences セクション追加、両 enum 一貫対応を明示 |
| Warning | 5 秒の根拠が薄い | 根拠を補強、ssh 体感トレードオフを Trade-off 表で明示 |
| Warning | 失敗種別区別の後送り根拠が薄い | A-3c で op の区別可能性を**先に調査**、結果次第で別 DR を起こす流れに変更 |
| Warning | fake clock 注入点・並行レーステスト戦略が DR にない | `Store::with_clock` 注入点 + tokio::test の並行ケースをテスト戦略に明示 |
| Info | 可観測性 (`status` / 診断ログ) が範囲外扱い | 本 DR の範囲に**含める**ことに変更 (= ループ防止と可視化は同時実装が筋良い) |

## Context

dogfood Phase 3 (cache-warden が日常 SSH の本番) 中、離席タイミングで TouchID が約 20 連発する現象を観測した (journal `docs/journal/2026-06-13-handoff-ecdsa-dogfood-stablewhich.md` §A、issue `docs/issue/2026-06-14-op-refetch-loop.md`)。

コード調査 (2026-06-14) で根本原因が確定:

1. `crates/cache-warden-cli/src/daemon/authsock.rs:989-992` の `lazy_load_op_key` は `runner.run` が `Err` を返したとき **`store.set` を呼ばずに `return false`**
2. `crates/cache-warden/src/store.rs:212-214` の `Store::regenerate` も同様、`RegenerateOutcome::RunFailed` で `store.set` をスキップ
3. entry は absent (= `state == NotLoaded` 相当) のまま残るため、次の SIGN_REQUEST / kv.get で同じ key を見るとまた fetch 経路に入り、op が再度 TouchID プロンプトを出す
4. **retry / backoff 機構は実装ゼロ** (`failed_at` / `backoff` / `last_failure` 等の grep ヒット皆無)

「op CLI が TouchID dismiss / timeout / 一時失敗で exit 非ゼロを返す」状況で、**接続元が SIGN_REQUEST を機械的に再送する** とループ化する。離席中で kawaz が TouchID を捌けない状況だと、op CLI の TouchID プロンプトが連続発火する。

## Decision

core `Store` に **failure 状態専用の別フィールド `failure_backoffs: BTreeMap<String, FailureRecord>`** を持たせ、fetch 経路 (`Store::regenerate` / `Store::get_or_regenerate`) の前段で **backoff 期間内なら新規 fetch を抑止し新 variant `RegenerateOutcome::Backoff` を返す**。`failure_backoffs` は `entries` / `definitions` と並列の**第 3 のマップ**で、failure 状態は両者から独立して持つ。

### 配置 (Critical #1 反映、改訂版)

`Entry` には持たせない:

- DR-0014 で確立した entries-only モデル: `Store::entries` は **値を持つ entry のみ** を保持する。definition-only な key は entries に存在しない
- 初回 lazy 失敗時 (= 値が一度も成功していない)、entry は物理的に作られず failure を書き込む先が無い
- `failure_backoffs: BTreeMap<String, FailureRecord>` を第 3 のマップとして持つ。`FailureRecord { failed_at: Instant, retry_after: Duration }` で必要十分

### 前提条件 (Critical #2 反映)

実装着手前に **`lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一する refactor が必要**:

- 現状: authsock 側が独自 fetch/set 経路を持つ (`lazy_load_op_key`)、`Store::get_or_regenerate` を通らない
- このまま core に backoff を入れても authsock 経路には効かない (= 「core 一本化」が嘘になる)
- → core 統合を**真に実現**するため、authsock 経路を core API 経由に統一する refactor を先行 (A-3a)
- 暫定 2 箇所判定 (= 初版の想定) は **採用しない** (= テスト穴 + 構造矛盾を作らない)

### 設計分類 (Warning #4 反映)

backoff は **TTL/pin と別カテゴリ** = 「source 実行の retry policy / circuit breaker」:

- TTL/pin は **値の寿命** (= 値が cached である間の生存時間と表示権限)
- backoff は **source 実行 (= 値の生成試行) の失敗履歴と次回試行の抑止**
- 「定義だけある NotLoaded 状態」(= 値が存在しない) でも backoff は意味を持つ (= 連続失敗 → 待つ) 一方、TTL/pin は意味を持たない (= 値が無いので寿命の概念がない)

この分類変更により、`failure_backoffs` を `definitions` 側のメタデータに混ぜず別マップにする整合性が取れる (= 定義は immutable な仕様、failure は mutable な状態)。

### backoff 期間 (Warning #5 反映)

- default `5s` (config `[daemon].fetch-failure-backoff`、`"0s"` で機能無効化)
- 5 秒の根拠:
  - TouchID 操作の典型反応時間 ≈ 3-5 秒 (kawaz が TouchID を捌けるようになる典型タイミング、勘所)
  - ssh のデフォルト `ConnectionAttempts = 1` = 1 回 `agent refused` を見たら諦め、retry しない
  - ControlMaster 再認証ケースで 5 秒程度なら user 体感の許容範囲
- 5 秒中の ssh 接続失敗トレードオフ (Warning #2 反映):
  - `agent refused` → ssh client が即諦め exit 1 (or ControlMaster 再認証時は 1 回の失敗) → ssh 側 retry 機構があれば 5 秒後の再試行で成功
  - backoff 機能の効果 (= TouchID 連発抑止) が ssh 側体感 (= 1 回の接続失敗) を上回るかは **dogfood で検証**
  - 検証結果が悪い場合: `[daemon].fetch-failure-backoff = "0s"` で無効化 + per-source 設定 (= `[kv.NAME].failure-backoff`) を Open Question として follow-up

## Alternatives Considered

### 案 A: backoff を adapter 層 (authsock) に乗せる

- ⚠️ control socket 経由の通常 `kv.get` でも同じ問題 → adapter 限定では半分しか塞げない
- ❌ 不採用 (= `for-all/rules/design-priority.md` 「より正しい設計を選んで全体を直す」原則)

### 案 B: 指数 backoff + retry count

- 1s → 2s → 4s → 8s …
- ⚠️ 原因が人間の TouchID 操作タイミングなので指数で延ばす意味が薄い
- ⚠️ retry count を保持する分 state が膨らむ
- ❌ 不採用 (= 固定で十分シンプル、必要なら follow-up で再評価)

### 案 C: 失敗種別ごとに backoff 長を変える (Warning #6 反映)

- op exit code / stderr で `dismiss` / `not signed in` / ネット一時失敗 / 認証情報不備を区別可能なら、それぞれ別の backoff
- ⏸ **A-3c で op の区別可能性を調査** (RealOpClient::run の error mapping + op の man / 既知挙動を確認)
- 区別可能なら別 DR (DR-0024 候補) として独立、本 DR は一律 5s で確定
- 区別不能なら一律 5s で確定 (本 DR で完結)

### 案 D: 失敗の可視化 (status / stderr 強化)

- 直交方向 → **本 DR の範囲に含める** (Info #8 反映): `status` / `kv list` 出力に `backoff_until: <t>` を載せる、stderr に `fetch failed (backoff active until <t>)` を 1 行追記
- = ユーザ・スクリプトが「鍵なし」「認証拒否」「backoff 中」を区別可能になる (= ループ防止と可視化を同時実装)

### 案 E (初版): `Entry` に `last_failure_at`

- Codex Critical #1 で否定 (= entries-only モデル違反、初回 lazy 失敗時に置き場が無い)
- 改訂版で `failure_backoffs` 別マップに変更

### 案 F (初版): authsock 側に暫定 backoff 重複

- Codex Critical #2 で否定 (= core 一本化と矛盾、テスト穴)
- 改訂版で「先に lazy load 統一」を前提条件に格上げ

## Consequences (Warning #3 反映)

### 公開 API 変更 (v2 改訂で W2 / I2 反映)

- `RegenerateOutcome` に新 variant `Backoff { retry_after: Duration }` 追加 → 既存 `match` を持つ library consumer は arm 追加が必要 (= 破壊変更)
- DR-0014 の lazy 生成経路で使われる `RegenerateDefOutcome` にも**同等の variant 追加** (= 両 enum 一貫適用、片方だけ対応はテスト穴)
- `Store::new()` (引数なし) を維持、新 setter `Store::set_failure_backoff(Duration)` で backoff 期間を後付け注入:
  - library consumer は `Store::new()` のままで OK (= 既存呼び出しは無破壊)、default `Duration::ZERO` で backoff 機能なし
  - daemon は startup 時に config から読んだ duration を `store.set_failure_backoff(duration)` で注入
  - `Store::with_failure_backoff(d)` 形の constructor は追加しない (= setter で十分、constructor variant 増加を回避)
  - = backoff は **daemon 固有の運用機能**、library 単体使用では disabled、という設計切り分けを明示
- public API 変更を `CHANGELOG.md` に明示、`crates/cache-warden` の semver は **minor bump** (= 0.x.y 段階なので minor で破壊 OK だが互換性宣言は誠実に)

### A-3a の scope と timeline (v2 改訂で C2 / X1 反映)

A-3a (`lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一) は **本 DR 実装の前提条件**として独立 PR で進める。本 DR (A-3b 本実装) は A-3a 完了後に着手。

- A-3a の予測 scope:
  - `crates/cache-warden-cli/src/daemon/authsock.rs` の `lazy_load_op_key` / `ensure_loaded` 周辺 (= 100-300 SLOC の refactor 想定)
  - `crates/cache-warden/src/store.rs` の `get_or_regenerate` シグネチャ拡張 (= auth context / requester chain を渡せるように)
  - 既存テスト (= authsock_e2e.rs / e2e.rs) の green 維持を前提
- A-3a が遅延する間の dogfood 実害は **`[daemon].fetch-failure-backoff` 無効化済み状態と等価** = op TouchID 連発の rate driver が止まらない可能性は残る
- 暫定対処は in-DR の範囲外:
  - dogfood 一時 rollback (= authsock-warden に戻す)
  - 手動 `op signin` / TouchID 捌きで凌ぐ
  - rate driver (= 接続元) を `lsof` で特定して根本側を直す (live 診断 runbook `docs/runbooks/op-refetch-loop-live-diagnosis.md`)
- **adapter 側暫定 backoff は採用しない** (X1 反映): 「暫定 2 箇所判定」を残すと core 一本化の構造的整合が崩れる。短期の dogfood 実害を許容して構造を優先する判断。kawaz の dogfood 体感が許容不能なら別途判断 (= say で確認)

### 可観測性 (v2 改訂で I1 / I2 反映)

- `status` / `kv list` 応答に `backoff_until: Option<seconds>` フィールド追加 (control socket protocol 拡張、DR-0009 minor extension)
- 失敗時 stderr ログの emit 位置:
  - core 側: `crates/cache-warden/src/store.rs` の `regenerate` 失敗 path で `tracing::warn!` (= consumer の log subscriber で受ける、stderr 直書きは avoid)
  - adapter 側: `crates/cache-warden-cli/src/daemon/authsock.rs:920` 周辺 (現状の sign 失敗時 `eprintln!`) に `(backoff active until <t>)` を追記
  - `crates/cache-warden-cli/src/commands/op_private_key.rs:57` の既存 op fetch 失敗 stderr に `(backoff active)` マーカーを追記
- authsock.rs 既存テスト (= `crates/cache-warden-cli/tests/authsock_e2e.rs`) の `Store` 構築箇所を `Store::new()` + `set_failure_backoff(Duration::ZERO)` または fake clock + 期間設定に改修 (= test isolation を維持)

### 状態管理 (v2 改訂で C1 / W1 / W3 反映)

- **lifetime は `definitions` と一致** (W3 反映): `failure_backoffs.<key>` は対応する `definitions.<key>` がある限り保持する。`kv.del --with-define` (定義削除) で `failure_backoffs.<key>` も削除、`kv.del` (値のみ削除) では残す (= 次の lazy load で backoff が効く、正常動作)、hard-ttl 切れ entry drop でも残す (= 定義がある限り failure 履歴は意味がある)
- **process restart で消える** (= in-memory only、永続化しない、W1 反映): 再起動後の最初の fetch は backoff を見ない。これは仕様で、continuous restart loop (= systemd / launchd で connection 失敗のたびに restart する malicious / buggy automation) は **cache-warden の脅威モデル外** = service manager (launchd / systemd) の責務
- **`Store::set` は `failure_backoffs` を触らない** (C1 反映): adapter 経由の static 値投入 (`kv.set`) でも `Store::set` を通るが、static 値投入で failure 履歴をリセットするのは意味的に違う (= adapter の static 投入と core の lazy fetch 成功は別事象)。`failure_backoffs` の更新は **`regenerate` / `get_or_regenerate` 経路の内部のみ**:
  - 失敗 path: `Store::regenerate` 内で `runner.run` / `auth` が `Err` 返却 → `failure_backoffs.insert`
  - 成功 path: `Store::regenerate` 内で `runner.run` 成功 + `store.set` 完了直後 (= 同じ Mutex 下) → `failure_backoffs.remove`
  - = `Store::set` は **immutable from failure_backoffs' perspective**

## Implementation Notes

### 順序 (= A-3a → A-3b → A-3c)

1. **A-3a (前提)**: `lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一する refactor。authsock e2e + signing matrix の回帰 green を確認
2. **A-3b (本実装)**: `failure_backoffs` + `RegenerateOutcome::Backoff` / `RegenerateDefOutcome::Backoff` + config + status / stderr 露出
3. **A-3c (follow-up)**: op の失敗種別区別調査、結果次第で別 DR

### 1. core Store の変更 (A-3b)

```rust
#[derive(Debug, Clone, Copy)]
pub struct FailureRecord {
    pub failed_at: Instant,
    pub retry_after: Duration,
    // pub kind: FailureKind, // A-3c 結果次第で追加
}

pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    failure_backoffs: BTreeMap<String, FailureRecord>,  // NEW
    failure_backoff_duration: Duration,                 // NEW
}
```

- `Store::regenerate` / `Store::get_or_regenerate` 冒頭で `failure_backoffs.get(key)` を見て、`failed_at + retry_after > now()` なら `Outcome::Backoff { retry_after: remaining }` を即返す
- `runner.run` 成功 → `failure_backoffs.remove(key)` (= リセット) + `store.set`
- `runner.run` / `auth` 失敗 → `failure_backoffs.insert(key, FailureRecord { failed_at: now, retry_after: self.failure_backoff_duration })`

### 2. config (A-3b)

```toml
[daemon]
fetch-failure-backoff = "5s"  # default 5s; "0s" で機能無効化
```

- `Duration` 文字列パーサは既存 `crates/cache-warden-cli/src/protocol/duration.rs` を流用
- `deny_unknown_fields` 互換 (DR-0010 流儀)

### 3. 可観測性 (A-3b, Info #8 反映)

- `status` / `kv list` 応答に `backoff_until: Option<seconds>` フィールド追加 (control socket protocol 拡張、DR-0009 minor extension)
- 失敗時 stderr ログに `(backoff active until <t>)` を追記 (`crates/cache-warden-cli/src/commands/op_private_key.rs:57` の既存ログを延長)
- backoff 中の `agent refused` log には `(backoff)` マーカー追記 (`crates/cache-warden-cli/src/daemon/authsock.rs` の失敗時 stderr)

### 4. テスト戦略 (Warning #7 反映)

`Store::new` のままで OK、ただし test では `Store::with_clock(clock: Arc<dyn Clock>, backoff: Duration)` を使い fake clock 注入点を明示 (= 既存設計から派生)。t-wada TDD でテスト先行:

1. **回帰**: fake op が exit 1、`Store::regenerate` は既存通り `Outcome::RunFailed` を返す
2. **新仕様 (red first)**: fake op exit 1 直後 (= clock 進めず) の `Store::regenerate` は新 `Outcome::Backoff` を返し、**fake op は再実行されない**
3. backoff 期間経過後 (fake clock 進める) に再呼出すと fake op が再実行される
4. backoff 中に `store.set` 直接呼出 (= 別経路で成功) → `failure_backoffs` クリア、以降 backoff なし
5. `failure_backoff_duration = 0s` で従来動作 (= backoff 機能なし、回帰)
6. **並行レース** (= Warning #7 補強): `tokio::test` で同一 key への 2 並行 `Store::regenerate` を起動、片方が失敗 → もう片方が backoff を見るかは Mutex 直列化に依存する。挙動を確定してテストで仕様化 (= 「Mutex で直列化済みなら 1 個目失敗 → 2 個目は backoff を見る」を期待として固定)
7. **lazy 経路** (= A-3a 後): `Store::get_or_regenerate` (DR-0014) の `RegenerateDefOutcome::Backoff` 経路でも同等の挙動を検証

## Open Questions (follow-up)

- **Q1 (= A-3c)**: 案 C (失敗種別区別) → op の exit code / stderr 区別可能性を調査、結果次第で別 DR
- **Q2**: `failure_backoffs` の永続化 (process restart 跨ぎ) は不要か → 不要 (= 再起動は新規セッション、過去失敗を持ち越さない)
- **Q3**: per-source / per-key の backoff 期間設定 (`[kv.NAME].failure-backoff = "10s"`) → ssh 体感のトレードオフ検証次第、follow-up
- **Q4**: 副次問題 (TouchID 中 Mutex 保持で blocking pool ストール、`docs/issue/2026-06-14-touchid-blocks-blocking-pool.md`) は本 DR の範囲外、別 issue で扱う
- **Q5** (v2 で W4 反映): backoff 中の SIGN_REQUEST に `agent refused` 以外の signal を返すべきか → SSH agent protocol に "retry later" 機構なし、`agent refused` 一択 (= 設計判断クローズ)。**ssh client 側の retry は外部頼み**: OpenSSH の `ConnectionAttempts` (= sshd 接続リトライ、agent には効かない) / `ssh-retry` ラッパー / mosh 等のセッション維持ツール / VS Code Remote SSH 等の auto-reconnect。control socket 経由 `kv.get` 経路は `RegenerateOutcome::Backoff` を `kv.get` レスポンスに乗せて backoff 残時間を提示する余地あり → follow-up issue で別検討
- **Q6** (v2 新): `failure_backoffs` の永続化 (Store の serialize / restore in handoff)。`graceful restart` (`docs/issue/2026-06-14-graceful-restart-state-handoff.md`) で kv + endpoint fd を新プロセスへ引き継ぐ際、`failure_backoffs` も引き継ぐべきか。直感は yes (= 直前の失敗履歴を新プロセスでも保持しないと restart で reset される) → graceful restart 設計の一部として詰める

## Related

- `crates/cache-warden-cli/src/daemon/authsock.rs:989-992` — `lazy_load_op_key` (A-3a で core API 経由に統一する対象)
- `crates/cache-warden/src/store.rs:212-214` — `Store::regenerate` (A-3b で backoff 判定追加対象)
- `crates/cache-warden/src/store.rs` の `Store` 構造体 (新 `failure_backoffs` フィールド追加対象)
- `crates/cache-warden-cli/src/commands/op_private_key.rs:57` — 既存の失敗時 stderr 診断 (整合確認)
- `crates/cache-warden-cli/src/daemon/authsock.rs:488` — 別経路の `authsock connection error` ログ (混同しないため記録、op-refetch loop 旧仮説の混同元)
- journal `docs/journal/2026-06-13-handoff-ecdsa-dogfood-stablewhich.md` §A — 現象発見の起点
- issue `docs/issue/2026-06-14-op-refetch-loop.md` — 本 DR が解の本体
- issue `docs/issue/2026-06-14-touchid-blocks-blocking-pool.md` — 副次問題、本 DR の範囲外
- DR-0011 (TTL 2 分離) — 分類比較対象 (TTL/pin と本 DR の retry policy は別カテゴリ)
- DR-0014 (entries-only モデル) — 本 DR の状態管理位置の前提
- DR-0009 (control socket protocol) — `status` の `backoff_until` フィールド追加で minor extension
