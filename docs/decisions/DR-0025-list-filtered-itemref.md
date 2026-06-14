# DR-0025: コア list API 改修 — ItemRef + list_filtered

- Status: Accepted
- Date: 2026-06-14
- Related: DR-0014 (entries / definitions 3 マップ分離、本 DR の構造的前提) / DR-0022 (failure_backoffs 第 3 マップ、本 DR の accessor 対象) / DR-0009 (control socket protocol、handler 書き換えで影響)

## Context

### 既存 list / keys の限界

`Store` は現在 2 つのリスト API を持つ:

```rust
// value entries のみ (entries map)
pub fn list(&self) -> Vec<&str>

// union (entries ∪ definitions、definition-only キーも含む)
pub fn keys(&self) -> Vec<&str>
```

どちらもキー文字列だけを返す。キーの状態・定義・バックオフ情報を得るには呼び出し元が個別に複数の
accessor を手動で横断する必要がある。

### handler の重複コード

`crates/cache-warden-cli/src/daemon/handler.rs` の `handle_status` はこのパターンを実装している:

```rust
// handle_status:202-214 (現状)
let names: Vec<String> = store.keys().iter().map(|s| s.to_string()).collect();
for name in names {
    let has_value = store.has_value(&name);
    let defined = store.is_defined(&name);
    let state = match store.state_of(&name, ctx.clock) { ... };
    let regenerable = defined || store.source_of(&name).map(|s| s.is_regenerable()).unwrap_or(false);
    let pin_remaining_secs = store.pin_deadline_of(&name).map(|deadline| ...);
    let value_type = store.definition_of(&name).map(|d| d.meta()) ...;
    let source = store.definition_of(&name).and_then(...);
    let backoff_until_secs = store.failure_backoff_remaining(&name, ctx.clock).map(|d| d.as_secs());
    entries.push(EntryInfo { ... });
}
```

`Request::KvList` 側も `store.keys()` を直接使っている:

```rust
// handle_request:118
Request::KvList => Response::list(store.keys().iter().map(|s| s.to_string()).collect()),
```

この「`keys()` → for ループ → 個別 accessor で 3 マップ横断」パターンは:

1. **呼び出し側の責務が肥大化する**: 各フィールドの lookup を handler が知らなければならない
2. **同じパターンが新しい呼び出し箇所でも繰り返される**: `snapshot_definitions` (defs.rs) も `store.keys()` ループを使っている
3. **フィルタリングが不可能**: `list()` は entries 固定、`keys()` は union 固定、中間状態でのフィルタができない。例えば「定義があって値がまだない key だけを返す」「backoff 中の key だけを返す」といった用途で新 API が必要になるたびに Store に追加することになる
4. **`state_of` は `&mut self`**: 現状 `handle_status` は mutable borrow と immutable borrow を交互に取るため、一旦 `names: Vec<String>` にコピーしてから再アクセスせざるを得ない

### 3 マップ横断の文脈

DR-0014 と DR-0022 で確立した Store の内部構造は 3 マップ:

- `entries: BTreeMap<String, CacheEntry>` — 値エントリ (TTL-gated、zeroize 対象)
- `definitions: BTreeMap<String, Definition>` — 定義レジストリ (値を含まない)
- `failure_backoffs: BTreeMap<String, FailureRecord>` — fetch 失敗履歴 (DR-0022)

「あるキーについての全メタデータを見る」操作は常にこの 3 マップを横断する。その横断を
adapter 層 (handler) が毎回手書きしているのが現状の問題である。

## Decision

### 1. ItemRef&lt;'a&gt; — lazy accessor handle 型

`crates/cache-warden/src/item_ref.rs` を新規作成し、`ItemRef<'a>` を定義する:

```rust
/// Store のキー 1 個に対する immutable borrow ハンドル。
///
/// 3 マップ (entries / definitions / failure_backoffs) への lazy 参照を
/// 束ねる。accessor は呼ばれた時点で対応するマップを lookup するため、
/// 呼び出さないフィールドの lookup ペナルティはゼロ。
///
/// `&mut Store` borrow (= zeroize 副作用を持つ state_of / evaluate) は
/// 保持しない。immutable borrow 1 個なので filter callback 中に side-effect
/// (hard-expiry zeroize 等) は発生しない。
pub struct ItemRef<'a> {
    key: &'a str,
    store: &'a Store,
}

impl<'a> ItemRef<'a> {
    pub fn key(&self) -> &str { self.key }

    /// 現時点の lifecycle state。zeroize 副作用なし (`&self` = pure read)。
    pub fn state(&self, clock: &impl Clock) -> Option<EntryState> {
        self.store.entries.get(self.key).map(|e| e.state(clock))
    }

    pub fn entry(&self) -> Option<&CacheEntry> {
        self.store.entries.get(self.key)
    }

    pub fn definition(&self) -> Option<&Definition> {
        self.store.definitions.get(self.key)
    }

    pub fn failure(&self) -> Option<&FailureRecord> {
        self.store.failure_backoffs.get(self.key)
    }

    pub fn failure_remaining(&self, clock: &impl Clock) -> Option<std::time::Duration> {
        self.store.failure_backoff_remaining(self.key, clock)
    }

    pub fn value_meta(&self) -> Option<&ValueMeta> {
        self.store.definitions.get(self.key).map(|d| d.meta())
    }

    pub fn source_meta(&self) -> Option<&SourceMeta> {
        self.store.definitions.get(self.key).map(|d| d.source_meta())
    }
}
```

**設計上の重要な選択**:

- `state` は `&self` で `CacheEntry::state` (pure read) を呼ぶ。`CacheEntry::evaluate` (zeroize 副作用あり) は呼ばない。hard-expiry zeroize は `Store::get` / `Store::state_of` (`&mut self`) の責務のまま変えない。
- accessor は「必要なものだけ呼ぶ」設計。例えば `failure_remaining` だけが必要な filter は他の 2 マップを lookup しない。
- `entry()` と `definition()` は個別に公開する。`ItemRef` はフラット snapshot 展開しない (後述の Alternatives を参照)。

### 2. list_filtered — メタデータベースの filter API

`Store` に以下のメソッドを追加する:

```rust
impl Store {
    /// 3 マップの union キー全体に対し、filter callback で絞り込んだ key 一覧を返す。
    ///
    /// callback は `ItemRef<'_>` を受け取り、含める場合 `true` を返す。
    /// `list_filtered(|_| true)` は `keys()` 相当、
    /// `list_filtered(|r| r.state(clock).is_some())` は value entries のみ (= `list()` 相当)。
    ///
    /// callback は immutable borrow のため side-effect 不可能 (pure 観察)。
    pub fn list_filtered<F>(&self, filter: F) -> Vec<&str>
    where
        F: Fn(&ItemRef<'_>) -> bool,
    {
        let mut keys: Vec<&str> = self
            .entries
            .keys()
            .chain(self.definitions.keys())
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys.dedup();

        keys.into_iter()
            .filter(|key| {
                let item = ItemRef { key, store: self };
                filter(&item)
            })
            .collect()
    }
}
```

clock を引数に含めないことに注意する。clock は filter callback の closure がキャプチャする。
これにより `list_filtered` 自体のシグネチャが Clock に依存せず、clock が不要な filter
(例: `|r| r.definition().is_some()`) では clock を渡さなくて済む。

### 3. 既存 list / keys の deprecation

```rust
/// value entries のみ。
///
/// # Deprecated
/// `list_filtered(|r| r.entry().is_some())` に置き換えること。
#[deprecated(note = "use list_filtered(|r| r.entry().is_some()) instead")]
pub fn list(&self) -> Vec<&str> { ... }

/// entries ∪ definitions の union。
///
/// # Deprecated
/// `list_filtered(|_| true)` に置き換えること。
#[deprecated(note = "use list_filtered(|_| true) instead")]
pub fn keys(&self) -> Vec<&str> { ... }
```

両 API は `#[deprecated]` を付けるが削除しない。library consumer との互換を保ちながら
移行を促す。削除は別 PR で semver major bump を伴って行う。

### 4. handler 側の書き換え

`handle_status` の 3 マップ手動横断ループを `list_filtered` + `ItemRef` accessor 経由に置き換える:

```rust
fn handle_status<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>) -> Response
where
    A: ?Sized,
    C: Clock,
{
    let now = ctx.clock.now();
    // list_filtered は &self なのでそのまま呼べる。
    // has_value / is_defined 等の個別 bool チェックは ItemRef accessor に委譲。
    let items = store.list_filtered(|_| true);
    let mut entries = Vec::with_capacity(items.len());

    for key in items {
        // state_of (&mut) はまだ必要 (zeroize 副作用を起こす正規経路)。
        // ItemRef::state は pure read のため status 報告用に使い、
        // zeroize は別途 state_of で起こすか、get 経路に任せる。
        // 実装詳細は Implementation Notes を参照。
        ...
    }
    ...
}
```

`Request::KvList` も同様:

```rust
Request::KvList => {
    let keys = store.list_filtered(|_| true);
    Response::list(keys.iter().map(|s| s.to_string()).collect())
}
```

## Alternatives Considered

### 案 A: フラット ItemSnapshot 展開 (不採用)

```rust
pub struct ItemSnapshot {
    pub key: String,
    pub state: Option<EntryState>,
    pub has_value: bool,
    pub is_defined: bool,
    pub failure_record: Option<FailureRecord>,
    pub value_meta: Option<ValueMeta>,
    pub source_meta: Option<SourceMeta>,
    // ...
}

pub fn list_all_snapshots(&self, clock: &impl Clock) -> Vec<ItemSnapshot> { ... }
```

**不採用理由**: 全フィールドを毎回 lookup する。例えば `kv list` (key 一覧表示だけ) では
`value_meta` や `source_meta` の lookup が不要だが、この案では常に全フィールドを展開する。
また `ItemSnapshot` が公開 API になると、フィールド追加のたびに semver break が生じる。
`ItemRef` の lazy accessor 方式なら必要なフィールドだけ呼べば良く、新フィールドの追加も
新 accessor を足すだけで既存 consumer に影響しない。

### 案 B: Vec&lt;ItemSnapshot&gt; 返却 + with_clock API (不採用)

案 A と本質的に同じ問題を持つ。`clock` を `list_all` レベルに持ち込むと、
clock が不要な用途でも引数が増える。

### 案 C: Store::item(key) -&gt; Option&lt;ItemRef&gt; 単独 lookup API のみ追加 (不採用)

```rust
pub fn item(&self, key: &str) -> Option<ItemRef<'_>> { ... }
```

これだけでは「全 key をフィルタして一覧化する」ユースケースが解決しない。handler が
`keys()` でキー列挙して `item(key)` で 1 件ずつ引くパターンになり、`store.keys()` の
依存は変わらない。`list_filtered` と組み合わせることで `item` API も自然に導出されるため、
本 DR では `list_filtered` を主軸とし、`item` の追加は Open Questions とする。

### 案 D: コア API 不変のまま handler 側に helper を持ち込む (不採用)

```rust
// handler.rs に内部 fn を追加
fn collect_entry_info(store: &mut Store, key: &str, clock: &impl Clock) -> EntryInfo { ... }
```

adapter 層で 3 マップ横断ロジックを関数化するだけ。コアの API 設計問題は残り、
「handler が Store 内部の 3 マップ構造を知らなければならない」という結合は変わらない。
新しい adapter (将来のデーモン実装 / テスト fixture) でも同じ helper を再実装することになる。
コアに `list_filtered` を置くことで横断ロジックがコア側に閉じ、adapter はフィルタ条件を
callback で持ち込むだけになる。

### 案 E: list_filtered に Clock を渡す (不採用の設計選択)

```rust
pub fn list_filtered<F, C>(&self, clock: &C, filter: F) -> Vec<&str>
where
    C: Clock,
    F: Fn(&ItemRef<'_>, &C) -> bool,
```

clock を第 1 引数に持つ設計も検討した。しかし clock が不要な filter
(`|r| r.definition().is_some()` 等) でも引数が増え、シグネチャが煩雑になる。
clock は closure キャプチャに任せれば「必要な filter だけが clock を使う」設計になり、
API がミニマルに保てる。

## Trade-off

**良い面**:
- handler の 3 マップ手動横断が消え、コアが責務を担う
- `ItemRef` の lazy accessor により「呼ばれたフィールドだけが lookup される」= 必要最小の lookup コスト
- filter callback に side-effect がない (immutable borrow) = 純粋な観察 API として推論しやすい
- 既存 `list` / `keys` は deprecation で残すため library consumer への影響が即時破壊にならない
- 新しい filter (例: 「backoff 中だけ」「OTP 型だけ」) は caller 側 callback で表現でき、コア API を増やさずに対応できる

**悪い面**:
- `ItemRef` は `state` で `CacheEntry::state` (pure read) を使う。hard-expiry zeroize は
  発生しない。status 報告で「hard-expired と表示したのに値がまだ zeroize されていない」
  ウィンドウが存在する。これは現在の `handle_status` が `state_of` (`&mut`) を呼んで
  zeroize していたのとの振る舞い差になる。実装時に zeroize の契約を明確化する必要がある
  (詳細は Implementation Notes を参照)。
- `list_filtered` は `&self` のため `state_of` (zeroize 副作用) を内部から呼べない。
  status 表示専用に「pure read の state」と「zeroize する evaluate」を使い分けることになる。
  この非対称は `CacheEntry::state` vs `CacheEntry::evaluate` の既存設計を踏襲しており、
  新たな非対称ではないが、handler 側で意識する必要はある。
- `ItemRef<'a>` は public 型として export される。将来 Store の内部フィールド構成が変わると
  `ItemRef` のシグネチャも影響を受ける可能性がある。

## Consequences

### 公開 API 変更

- `crates/cache-warden/src/item_ref.rs` 新規追加 (新規 public 型 `ItemRef<'a>`)
- `Store::list_filtered` 追加 (新規 public メソッド)
- `Store::list` / `Store::keys` に `#[deprecated]` 付与 (既存 API を壊さない)
- `lib.rs` の `pub use` 更新 (`ItemRef` を crate root に re-export)
- semver: **minor bump** (新規 API 追加のみ、既存 API は deprecated で残す)
- `CHANGELOG.md` に明示

### handler 書き換え

- `crates/cache-warden-cli/src/daemon/handler.rs:handle_status` の手動横断ループを
  `list_filtered` + `ItemRef` accessor 経由に書き換える
- `Request::KvList` も `list_filtered(|_| true)` に書き換える
- `defs.rs:snapshot_definitions` の `store.keys()` ループも将来的に `list_filtered` に
  移行する (本 DR のスコープには含めるが、`#[deprecated]` 警告が出た時点で対応でも可)

## Implementation Notes

### ファイル構成

```
crates/cache-warden/src/
  item_ref.rs   (新規)
  store.rs      (list_filtered 追加、list/keys に deprecated)
  lib.rs        (ItemRef を pub use)
```

### zeroize タイミングの扱い

`ItemRef::state` は `CacheEntry::state` (pure read、副作用なし) を使う。
`handle_status` が現在 `state_of` (`&mut`、zeroize 副作用あり) を呼んでいた挙動との差は以下:

- status 表示: `ItemRef::state` で表示 (pure read、zeroize なし)
- zeroize: `store.get` や `store.state_of` が呼ばれた時点で自然に発生する (通常の get 経路)

status 経由で hard-expired キーが長時間 zeroize されない問題は現実的に小さい (次の `kv get`
で zeroize される)。DR-0007 の脅威モデル (mlock + RLIMIT_CORE でスワップ / core dump から守る)
の範囲内であり、status ループが意図的に zeroize を起こす必要はない。

実装時の具体的判断: handler 書き換えで明示的に `state_of` を呼ぶ行を残す必要があるかどうかは
コードレビューで確認する。

### ItemRef の visibility

`ItemRef` は `pub(crate)` にする案もあるが、外部ライブラリ consumer が独自 filter を書く
可能性を考慮して `pub` とする。`list_filtered` のシグネチャ上 `ItemRef` が引数型として
現れるため、いずれにしても public 型にする必要がある。

### テスト戦略

t-wada TDD で実装:

1. `list_filtered(|_| true)` が既存の `keys()` と同じ結果を返すことを確認
2. `list_filtered(|r| r.entry().is_some())` が既存の `list()` と同じ結果を返すことを確認
3. filter callback が `ItemRef` 各 accessor を正しく返すことを個別に確認
4. `handle_status` の書き換え後も既存のハンドラテストが緑を維持することを確認
5. `Request::KvList` の書き換え後も `list_returns_sorted_keys` テストが緑を維持することを確認

## Open Questions

### Q1: `Store::item(key) -&gt; Option&lt;ItemRef&lt;'_&gt;&gt;` の追加

単独 key lookup 用 API として `Store::item(key)` を追加すると、`handle_get` 等で
「このキーの定義を見たい」ケースで `definition_of(key)` の代わりに
`store.item(key).and_then(|r| r.definition())` と書けるようになる。
現時点では list / filter ユースケースを優先し、`item` の追加は本 DR に含めない。

### Q2: mutable ItemRef (ItemMut&lt;'a&gt;) の将来性

将来 `list_filtered_mut` (例: 「全 active キーを一括 extend する」) のような API が必要になった場合、
`ItemRef<'a>` から分岐した `ItemMut<'a>` 型が必要になる可能性がある。現時点では immutable read
のみで十分であり、mutable 版は separate DR として判断する。

## Related

- `crates/cache-warden/src/store.rs:407-533` — 既存 `list` / `keys` / accessor 群
- `crates/cache-warden-cli/src/daemon/handler.rs:128-200` — `handle_status` (3 マップ手動横断、書き換え対象)
- `crates/cache-warden-cli/src/daemon/handler.rs:86` — `Request::KvList` (書き換え対象)
- `crates/cache-warden-cli/src/defs.rs:70-105` — `snapshot_definitions` (将来的な移行対象)
- DR-0014 `docs/decisions/DR-0014-kv-definition-model.md` — 3 マップ分離の起源 (entries / definitions)
- DR-0022 `docs/decisions/DR-0022-fetch-failure-backoff.md` — failure_backoffs 第 3 マップ (ItemRef の accessor 対象)
- DR-0009 `docs/decisions/DR-0009-control-socket-protocol-v1.md` — control socket protocol (handler 書き換えで影響するプロトコル層)
