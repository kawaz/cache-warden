# lazy-load-op-key-unification-plan: `lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一する refactor 計画

> 参照元: [DR-0022](../decisions/DR-0022-fetch-failure-backoff.md) §前提条件 (A-3a)
> 前提 DR: [DR-0014](../decisions/DR-0014-kv-definition-model.md) / [DR-0018](../decisions/DR-0018-typed-sources-auth-and-prefetch.md) / [DR-0022](../decisions/DR-0022-fetch-failure-backoff.md)

本文書は DR-0022 (fetch-failure-backoff) の前提条件 A-3a として要求される refactor の
設計・実装計画書である。`lazy_load_op_key` の独自 fetch/set 経路を廃し、
`Store::get_or_regenerate` 経由に統一することで、core API の実装を「片面」から「完全実装」へ移行する。

---

## 1. 現状調査

### 1.1 `lazy_load_op_key` の実装

**ファイル**: `crates/cache-warden-cli/src/daemon/authsock.rs:964-1007`

```
fn lazy_load_op_key<A, R, C>(
    store: &mut Store,
    key: &str,
    argv: &[String],
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
    auth: &A,
    runner: &R,
    requester: Option<&[ProcessInfo]>,
    clock: &C,
) -> bool
```

**引数**:
- `store: &mut Store` — ストア直接参照 (core API を経由しない)
- `key: &str` — 内部 KV キー (`__authsock_op:<item_id>` 形式)
- `argv: &[String]` — `op item get ... --reveal` の argv (`KeySource::Op.argv`)
- `soft_ttl_secs / hard_ttl_secs: Option<u64>` — source の TTL 設定
- `auth: &A` — 認証ゲート
- `runner: &R` — コマンドランナー (実際には `self` バイナリの `__authsock-op-private-key` サブコマンドを呼ぶ)
- `requester: Option<&[ProcessInfo]>` — SIGN_REQUEST 発行者の ancestry chain
- `clock: &C` — 単調クロック

**戻り値**: `bool` — `true` = Active になった / `false` = 失敗 (denied / fetch error)

**副作用**:
1. `runner.run(argv, None, &BTreeMap::new())` で PEM を取得 (`cwd=None`, `env=空`)
2. `auth.authenticate(&AuthContext::regenerate(key).with_requester(...))` で再認証
3. 成功時のみ `store.set(key, ValueSource::command(argv.to_vec()), value, ttl, clock)` でコアに直接投入
4. 失敗時 (run/auth どちらでも) は `store.set` を呼ばない → entry は absent のまま残る (= op-refetch loop の根本)

**run 呼出パターン** (`authsock.rs:989-992`):
```rust
let value = match runner.run(argv, None, &std::collections::BTreeMap::new()) {
    Ok(v) => v,
    Err(_) => return false,
};
```
- `cwd = None`、`env = 空 BTreeMap` 固定 (DR-0018 で「authsock の op パスは internal」と明記)

**store.set 呼出パターン** (`authsock.rs:1005`):
```rust
store.set(key, ValueSource::command(argv.to_vec()), value, ttl, clock);
```
- `define` は呼ばない → 定義レジストリへの登録ゼロ
- `ValueSource::command(argv.to_vec())` で command source として直接投入
- 後続の hard-expiry 後の `regenerate` は `store.regenerate` 経路 (ensure_loaded:940) が担う

**auth ゲート呼出経路** (`authsock.rs:998-1002`):
```rust
let ctx = match requester {
    Some(chain) => AuthContext::regenerate(key).with_requester(chain.to_vec()),
    None => AuthContext::regenerate(key),
};
if auth.authenticate(&ctx).is_err() {
    return false;
}
```
- `AuthOperation::Regenerate` を使用 (= core の regenerate と同一コンテキスト種別)

**内部 KV キー命名規約** (`authsock.rs:218-219`):
```rust
fn op_kv_key(item_id: &str) -> String {
    format!("__authsock_op:{item_id}")
}
```
- `__authsock_op:` prefix で手動 `[kv.*]` エントリとの衝突を回避
- DR-0018 §4.5 で `authsock/<NS>` への正規化が予定されているが未実装

**呼び出し元: `ensure_loaded`** (`authsock.rs:897-953`):

```rust
fn ensure_loaded<A, R, C>(store, key, source, auth, runner, requester, clock) -> bool {
    match store.state_of(key, clock) {
        None => match source {
            KeySource::Local => false,
            KeySource::Op { argv, soft_ttl_secs, hard_ttl_secs } =>
                lazy_load_op_key(store, key, argv, *soft_ttl_secs, *hard_ttl_secs,
                                 auth, runner, requester, clock),
        },
        Some(EntryState::Active) => true,
        Some(EntryState::SoftExpired) =>
            matches!(store.extend_authenticated(key, auth, requester, clock), Ok(())),
        Some(EntryState::HardExpired) =>
            match store.regenerate(key, runner, auth, requester, clock) {
                Ok(()) => true,
                Err(RegenerateOutcome::NotFound | ...) => false,
            },
    }
}
```

`ensure_loaded` は `sign_local_with_ctx` (`authsock.rs:855`) から呼ばれる。
store の Mutex ロックを保持したまま `lazy_load_op_key` を実行するため、
TouchID 中は Mutex を手放さない (= issue `docs/issue/2026-06-14-touchid-blocks-blocking-pool.md` の根本)。

### 1.2 `Store::get_or_regenerate` の現実装

**ファイル**: `crates/cache-warden/src/store.rs:457-502`

**シグネチャ**:
```rust
pub fn get_or_regenerate(
    &mut self,
    key: &str,
    runner: &impl SourceRunner,
    auth: &(impl Authenticator + ?Sized),
    requester: Option<&[ProcessInfo]>,
    clock: &impl Clock,
) -> Result<(), RegenerateDefOutcome>
```

**戻り値 (`RegenerateDefOutcome`)**:
- `Ok(())` — 値を新規生成して Active になった
- `Err(Undefined)` — 定義レジストリにキーがない
- `Err(ValueResident)` — Active or SoftExpired な値が既存 (再生成不要、caller が `get`/`extend` する)
- `Err(RunFailed(RunError))` — コマンド実行失敗
- `Err(AuthFailed(AuthError))` — 認証拒否

**内部の処理フロー** (`store.rs:464-501`):
1. `self.definitions.get(key)` — 定義レジストリを引く。なければ `Undefined`
2. `self.entries.get_mut(key)` で値の存在確認。Active or SoftExpired なら `ValueResident` を即返す
3. definition から `(argv, cwd, env)` を取り出す
4. `runner.run(&argv, cwd.as_deref(), &env)` — upstream 実行 (run → auth の順序は `regenerate` と同じ)
5. `auth.authenticate(&auth_context(key, AuthOperation::Regenerate, requester))` — 再認証
6. 成功時: `self.entries.insert(key, CacheEntry::new(source, value, ttl, clock))` で Active エントリを投入

**`definitions` レジストリとの連動**:
- `get_or_regenerate` は `Store::define` / `Store::define_with_meta` で事前登録された定義に基づく
- 定義がなければ機能しない (`Undefined` を返す)
- 定義の TTL・ValueSource を使ってエントリを生成するため、呼び出し元が TTL を渡す必要がない

**既存テストカバレッジ** (`store.rs:1381` 付近のテスト群):
- `define_registers_without_producing_a_value` — lazy 定義が run を行わないことを確認
- `get_or_regenerate_produces_value_from_definition` — 正常系 (ValueSource::Command)
- `get_or_regenerate_returns_value_resident_when_active` — 既存 Active は再生成しない
- `get_or_regenerate_run_failed_leaves_store_unchanged` — 失敗時の副作用なし確認
- `get_or_regenerate_auth_failed_zeroizes_fetched_value` — auth 拒否時の zeroize 確認

---

## 2. ギャップ分析

`lazy_load_op_key` と `Store::get_or_regenerate` の API ギャップを以下に整理する。

### 2.1 `lazy_load_op_key` が直接行っていて core API にないこと

| 項目 | lazy_load_op_key | get_or_regenerate |
|------|-----------------|-------------------|
| **Ttl 構築** | 呼び出し元から `soft_ttl_secs` / `hard_ttl_secs` を受け取り内部で `Ttl::new()` する | 定義レジストリの Ttl を使う (呼び出し元不要) |
| **ValueSource 構築** | 内部で `ValueSource::command(argv.to_vec())` を組み立てる | 定義レジストリの source を使う |
| **定義登録 (`define`) の有無** | `store.define` を呼ばない (定義レジストリへの登録なし) | 事前に `store.define` が必要 |
| **`cwd` / `env`** | `None` / 空 BTreeMap 固定 (DR-0018 内部パス) | 定義の `cwd` / `env` を使う |

### 2.2 core API に渡せていない情報

| 欠落情報 | 現状 | 統合後 |
|---------|------|--------|
| **auth context / requester chain** | `lazy_load_op_key` が直接 `AuthContext::regenerate(key).with_requester(...)` を組む | `get_or_regenerate` は `requester: Option<&[ProcessInfo]>` を受け取り同様に構築する → 変更不要 |
| **source 情報 (argv / TTL)** | `KeySource::Op { argv, soft_ttl_secs, hard_ttl_secs }` として authsock 側が保持し、lazy_load_op_key に渡す | 定義レジストリへの事前登録に移行すれば core が保持する |
| **`cwd` (未設定)** | `None` 固定 | 定義レジストリへの登録時に `cwd = None` で登録するのと等価 |
| **`env` (未設定)** | 空 BTreeMap 固定 | 定義レジストリへの登録時に `env = 空` で登録するのと等価 |

### 2.3 戻り値の不一致

| 観点 | lazy_load_op_key | get_or_regenerate |
|------|-----------------|-------------------|
| **型** | `bool` | `Result<(), RegenerateDefOutcome>` |
| **成功の意味** | `true` = 値が Active になった | `Ok(())` = 値を新規生成した |
| **失敗の詳細** | `false` (原因を区別しない) | `RunFailed` / `AuthFailed` / `Undefined` / `ValueResident` (原因別) |
| **DR-0022 backoff との接点** | `store.set` を呼ばずに `false` → backoff に記録できない | `RunFailed` / `AuthFailed` パスで backoff 記録を追加可能 (DR-0022 A-3b) |

この戻り値の差が DR-0022 の前提条件となる根本理由である。`lazy_load_op_key` が `false` を返すだけでは、
core の `failure_backoffs` マップ (DR-0022 で追加予定) への記録が「core 経由でない」ため効かない。

### 2.4 DR-0014 との関係 (片面実装の正体)

DR-0014 §2 は「定義レジストリと値ストアの分離、lazy 生成は `get_or_regenerate` 経路」を確立した。
しかし op 鍵の lazy load は:

- `store.define` を呼ばない → 定義レジストリに登録されない
- `get_or_regenerate` を使わない → DR-0014 の lazy 生成経路を通らない
- `store.set` を直接呼ぶ → ValueSource / TTL 情報が定義レジストリではなく値エントリにのみ存在する

`kv.del KEY` (値のみ削除) 後に定義レジストリから再生成できるのは `get_or_regenerate` 経路のみであるが、
op 鍵はその経路に乗っていないため `del` 後は `regenerate` (hard-expiry 後の `ensure_loaded:940`) 経路でのみ復旧できる。
これが「DR-0014 自体への片面実装」の実体である。

---

## 3. 統合戦略

### case 1: `lazy_load_op_key` を薄いラッパとして残し、内部を core API 呼び出しに変える

**Pros**:
- 呼び出し元 (`ensure_loaded`) の変更が不要
- `lazy_load_op_key` というエントリポイントを残すことで、op 鍵固有の「事前登録済みチェック」などを後で追加しやすい
- 差分が小さく、既存テストの修正量が少ない

**Cons**:
- `lazy_load_op_key` という関数名が「実はただのラッパ」になり、名前と実態が乖離する
- 関数が薄くなるだけで削除されないため、読者は 2 層 (ラッパ + core) を追わなければならない
- DR-0014 の「lazy 生成は `get_or_regenerate`」を直接示す構造にならない

### case 2: `lazy_load_op_key` を完全削除、呼び出し元を直接書き換える

**Pros**:
- DR-0014 の「lazy 生成は `get_or_regenerate`」が構造上自明になる
- 冗長な関数が消え、コードの読者が追うべき経路が 1 層減る
- `lazy_load_op_key` のテストを別途書かなくてよい (core の `get_or_regenerate` テストで担保)
- DR-0022 の backoff が op 鍵経路に自動的に効くことが構造的に保証される

**Cons**:
- `ensure_loaded` の変更が必要 (1 ブランチの書き換え、影響は局所)
- `lazy_load_op_key` の既存単体テスト (authsock.rs 内の `op_key_*` 群) のうち core API で重複するものは削除・移植が必要
- op 鍵の「定義登録」がどのタイミングで行われるかを追うには `register_op_keys` まで遡る必要がある

### 評価マトリクス

| 評価軸 | case 1 (薄いラッパ) | case 2 (完全削除) |
|--------|--------|--------|
| コード距離 | 小 (呼び出し元変更なし) | 小〜中 (ensure_loaded 1 ブランチ) |
| 振る舞い同値性 | 同値 (ラッパが透過) | 同値 (同じ core 経路を使う) |
| テストカバレッジ | lazy_load_op_key のラッパテストが残る | core テストに集約、重複なし |
| DR-0014 整合性 | 間接的に適合 | 直接適合 |
| DR-0022 前提 | 充足 | 充足かつ構造的に明白 |
| 将来の拡張 | ラッパが残るため op 固有ロジックを追加しやすい | core に追加する方が一貫する |

**推奨**: **case 2** (§7 参照)

---

## 4. 統合手順 (case 2 採用)

### step 1: 前提整備 — op 鍵の `define` 登録追加

**対象ファイル**: `crates/cache-warden-cli/src/daemon/authsock.rs:188-214`

`register_op_keys` が `registry.register_op_key(...)` を呼ぶ箇所で、
同時に `store.define(kv_key, ValueSource::command(argv), ttl)` を呼ぶ必要がある。

**方針 (= 自律判断、計画書 §7 のチェックリスト #2)**: `register_op_keys` のシグネチャ変更を避け、
**`spawn_listeners` 内** (`authsock.rs:282-295`) でソケットごとの op 鍵登録後に、
該当 store への `define` を一括実行する。`store` は `shared.store` (Mutex) を通して参照する。

**注意点**:
- `Define::new` は `ValueSource::Static` を拒否するので `ValueSource::command(argv)` を渡す
- `define` の冪等規則 (DR-0014 §1): 同一 `(argv, TTL)` の再登録は `Ok(())` (no-op)。daemon 再起動等で再実行されても安全
- `define` 失敗時 (= `DefineError::Conflict` etc.) は当該 op 鍵をスキップ + stderr 警告 1 行 (既存の `register_op_key` 失敗パターンと同じ流儀)

### step 2: テスト追加 (TDD、t-wada 流儀)

**red 段階 (先にテストを書く)**:

追加するテストケース (authsock.rs の `#[cfg(test)]` 内):
1. `op_key_registers_definition_in_store_at_spawn` — `register_op_keys` 相当のセットアップ後に `store.is_defined(kv_key)` が true
2. `op_key_lazy_load_goes_through_get_or_regenerate` — `store.get_or_regenerate` が呼ばれることを確認 (Spy Runner で確認)
3. `op_key_fetch_failure_does_not_create_definition_entry` — run 失敗後も define は消えない (= `kv del` 後の再試行が可能)

**注意**: step 2 の時点では `lazy_load_op_key` はまだ残っているため、テストは fail する (red)。

### step 3: `lazy_load_op_key` 内部を core API 経由に書き換え

**対象**: `crates/cache-warden-cli/src/daemon/authsock.rs:897-1007`

`ensure_loaded` の `None => KeySource::Op { ... } =>` ブランチを:

```rust
// 変更前
KeySource::Op { argv, soft_ttl_secs, hard_ttl_secs } =>
    lazy_load_op_key(store, key, argv, *soft_ttl_secs, *hard_ttl_secs,
                     auth, runner, requester, clock),

// 変更後
KeySource::Op { .. } =>
    matches!(store.get_or_regenerate(key, runner, auth, requester, clock),
             Ok(()) | Err(RegenerateDefOutcome::ValueResident)),
```

`get_or_regenerate` が `ValueResident` を返すのは Active / SoftExpired な値が既存の場合で、
この場合は後続の `store.get(key, clock)` が値を返せるため `true` として扱う (= 自律判断、計画書 §7 のチェックリスト #4)。
ただし SoftExpired は `ensure_loaded` の別ブランチ (`SoftExpired => extend_authenticated`) で
先に捕捉されるため、実際には `ValueResident` が返るのは想定外。

`lazy_load_op_key` 関数定義を削除する。

### step 4: 回帰テスト

実行順序:
1. `cargo test -p cache-warden` — core 単体テスト (define / get_or_regenerate / regenerate)
2. `cargo test -p cache-warden-cli` (unit) — authsock.rs 内の `#[cfg(test)]` 群
   - `op_key_first_sign_lazily_loads_fetches_and_signs`
   - `op_key_second_sign_within_soft_hits_cache_no_refetch`
   - `op_key_after_hard_expiry_regenerates_via_same_command`
   - `op_key_first_sign_denied_auth_loads_nothing_and_fails`
   - `op_key_fetch_failure_skips_auth_and_fails`
3. E2E テスト:
   - `op_source_discovers_key_and_signs_lazily` (authsock_e2e.rs:846)
   - `op_source_sign_with_denied_auth_is_failure` (authsock_e2e.rs:915)
   - signing matrix (e2e.rs 内の signing 系テスト全般)
   - control socket e2e (e2e.rs:72 `full_lifecycle_over_control_socket`)

### step 5: cleanup

1. `lazy_load_op_key` 関数定義を削除 (step 3 で実施済み)
2. `lazy_load_op_key` に関連していた `Ttl::new` の呼び出し箇所が消えるため、import の整理
3. `ensure_loaded` の引数リストから `argv` / `soft_ttl_secs` / `hard_ttl_secs` が消える
4. `#[allow(clippy::too_many_arguments)]` が `lazy_load_op_key` と `ensure_loaded` 双方に付いているが、cleanup 後は引数が減るため外せる可能性がある (要確認)

---

## 5. リスク + 既知の落とし穴

### 5.1 DR-0018 §4.5 の internal NS 正規化 (`authsock`) との関係

DR-0018 §4.5 で `__authsock_op:<item_id>` (正規文字種外の擬似 prefix) を廃止し、
予約 namespace `authsock` の正規キー (`authsock/op_<itemid>` 等) に移す計画がある。

**現状**: 未実装。`op_kv_key` 関数 (`authsock.rs:218`) が `__authsock_op:` prefix を返している。

**本 refactor との関係**:
- 本 refactor では キー名はそのまま (`__authsock_op:<item_id>`) で実施する
- NS 正規化と本 refactor を同時に行うと差分が大きくなり、回帰テストの失敗原因特定が困難
- **自律判断 (計画書 §7 のチェックリスト #1)**: 本 refactor (A-3a) を先に完了、NS 正規化は別 PR で後実施
- NS 正規化後は `store.define` の key も新 NS 形式に揃える必要があり、`kv list` / `status` の表示も変わる

### 5.2 TouchID 中の Mutex 保持との関係

`docs/issue/2026-06-14-touchid-blocks-blocking-pool.md` の副次問題:
現状は Mutex ロック保持中に `lazy_load_op_key` (= op fetch + auth = TouchID 待ち) を実行している。

**本 refactor 後の変化**:
- `get_or_regenerate` も `store: &mut Store` で呼ぶ = Mutex を保持したまま実行する
- つまり **blocking pattern は変わらない**
- `sign_local_with_ctx` が `ctx.store.lock()` してから `ensure_loaded` → `get_or_regenerate` まで Mutex を保持する構造は維持される
- TouchID ブロッキング問題は本 refactor では解消されない (別 issue で扱う)

### 5.3 regression test の coverage gap

**現状の懸念**:
- `op_key_fetch_failure_skips_auth_and_fails` (authsock.rs:1650) はフェッチ失敗をテストするが、
  「失敗後の再度 SIGN_REQUEST が再試行するか」 (= op-refetch loop の原因) はテストしていない
- E2E で「fetch 失敗 → 再 SIGN → backoff が効く (または無限に呼ばれる)」を確認するテストがない
  (これは DR-0022 A-3b のスコープだが、A-3a 完了後に追加すべき)

**本 refactor で追加すべきテスト**:
- `op_key_fetch_failure_does_not_set_entry` — run 失敗後に `store.has_value(key)` が false であること
- `op_key_definition_registered_at_spawn` — daemon 起動相当のセットアップ後に `store.is_defined(kv_key)` が true

### 5.4 public key derivation (register_op_key) との関係

`register_op_keys` (authsock.rs:188) は:
1. 公開鍵レジストリ (`PublicKeyRegistry`) への登録 (`registry.register_op_key`)
2. (追加予定) コア `Store` への定義登録 (`store.define`)

の 2 つを行う。

**リスク**: `define` が成功したが `register_op_key` が失敗した場合 (逆も然り)、
レジストリと定義が不整合になる。

**対処**: エラー発生時は当該 op 鍵をスキップ (両方をロールバックか、両方ともスキップ)。
既存コードは `register_op_key` 失敗時に `eprintln!` してスキップしているので、
`define` も同様にスキップすれば整合する。

---

## 6. テスト戦略

### 6.1 既存テストの影響範囲

**authsock_e2e.rs (1141 行) の影響範囲**:
- `op_source_discovers_key_and_signs_lazily` (L846) — 本 refactor で変わるべき経路を E2E で検証する中核テスト。**影響あり (振る舞いは同値のまま green であること)**
- `op_source_sign_with_denied_auth_is_failure` (L915) — auth 拒否時 FAILURE。**影響あり (同様)**
- `op_private_key_subcommand_extracts_pem_from_op_json` (L977) — `__authsock-op-private-key` サブコマンド単体テスト。**影響なし**
- `allowed_process_in_ancestry_permits_enumeration` / `disallowed_process_is_refused_and_hides_keys` — **影響なし** (process gate は本 refactor と直交)

**e2e.rs (1702 行) の影響範囲**:
- `full_lifecycle_over_control_socket` (L72) 系 — control socket 経由の `kv.*` コマンド群。op 鍵が定義レジストリに載ることで `kv list` / `kv status` の表示が変わりうる。**要確認**
- signing matrix テスト — op 鍵を使う署名テストがあれば **影響あり**

**authsock.rs unit tests (1009-1924 行) の影響範囲**:
- `op_key_*` 系 (L1517-1686) — 全て `sign_local_with_ctx` 経由で `lazy_load_op_key` を間接的に呼ぶ。本 refactor 後は `get_or_regenerate` 経由になるが、observable な振る舞いは変わらないため **green を維持すること**
- `register_op_keys_namespaces_and_threads_account_and_ttls` (L1721) — `register_op_keys` の戻り値と registry の状態を確認。`define` 追加後は store の状態確認も追加する

### 6.2 新規追加すべきテストケース

t-wada 流儀: red → green → refactor

**red (先に書く、step 3 前)**:
```rust
#[test]
fn op_key_lazy_load_uses_core_definition_path() {
    // store.is_defined(kv_key) が register_op_keys 後に true になること
}

#[test]
fn op_key_fetch_failure_does_not_create_definition_entry() {
    // run 失敗後も define は消えない
    // = kv del (値のみ削除) 後に get_or_regenerate で再試行できること
}
```

**green (step 3 後に pass する)**:
- 既存の `op_key_first_sign_lazily_loads_fetches_and_signs` が `get_or_regenerate` 経由で green

**refactor**:
- `lazy_load_op_key` のテストは `ensure_loaded` + `get_or_regenerate` の組み合わせテストに統合

---

## 7. 推奨 case の決定 + 実装着手チェックリスト

### 推奨: case 2 (完全削除)

**理由**:
1. **DR-0014 整合性**: `lazy_load_op_key` という独自経路を消すことで「lazy 生成は `get_or_regenerate` 経路」が構造的に自明になる
2. **DR-0022 前提の完全充足**: core の `failure_backoffs` マップが op 鍵経路に自動的に効くことが保証される
3. **コード量の削減**: `lazy_load_op_key` 関数 (約 44 行) と重複する `Ttl::new` 構築ロジックが消える
4. **テストの一本化**: op 鍵の lazy 生成は core の `get_or_regenerate` テスト群でカバーされるため、authsock 層でのテストは「define が呼ばれることの確認」に絞れる

### 実装着手チェックリスト (= 自律判断結果)

| # | 項目 | 判断 |
|---|------|------|
| 1 | NS 正規化との順序 | **本 refactor 先、NS 正規化は後続 PR** (= 差分肥大回避) |
| 2 | `define` 登録の置き場 | **`spawn_listeners` 内で別途呼ぶ** (= `register_op_keys` シグネチャ変更を避ける) |
| 3 | `define` 失敗時の op 鍵スキップポリシー | **`Conflict` は no-op、それ以外は op 鍵スキップ + stderr 警告** (= 既存 `register_op_key` 失敗パターンと同流儀) |
| 4 | `ValueResident` 扱い | **`true` 扱い (= 安全側)** |
| 5 | E2E の `kv list` / `status` 変化 | **実装中に観測、必要なら E2E 更新** |
| 6 | `authsock NS の kv.get 拒否 (DR-0018 §4.5)` の先行実装 | **本 refactor 範囲外、別 issue で扱う** |
| 7 | `just ci` の事前通過 | **実装前に確認** (回帰起点の明確化) |

---

## 関連

- `crates/cache-warden-cli/src/daemon/authsock.rs:897-1007` — `ensure_loaded` / `lazy_load_op_key` (変更対象)
- `crates/cache-warden-cli/src/daemon/authsock.rs:188-214` — `register_op_keys` (define 登録を追加する対象)
- `crates/cache-warden/src/store.rs:457-502` — `Store::get_or_regenerate` (統合先)
- `crates/cache-warden/src/store.rs:352-390` — `Store::define` / `Store::define_with_meta` (新規呼び出し対象)
- `crates/cache-warden-cli/tests/authsock_e2e.rs:846` — E2E 回帰テスト中核
- [DR-0014](../decisions/DR-0014-kv-definition-model.md) — 定義レジストリと値ストアの分離
- [DR-0018](../decisions/DR-0018-typed-sources-auth-and-prefetch.md) §4.5 — authsock NS 正規化 (後続 PR)
- [DR-0022](../decisions/DR-0022-fetch-failure-backoff.md) — 本 refactor の依頼元 (A-3a)
- [docs/issue/2026-06-14-touchid-blocks-blocking-pool.md](../issue/2026-06-14-touchid-blocks-blocking-pool.md) — Mutex 保持問題 (本 refactor の範囲外)
