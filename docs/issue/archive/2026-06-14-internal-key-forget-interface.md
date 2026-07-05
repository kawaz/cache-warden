---
title: コア公開 API レイヤで KEY / NS validation 強制 (= アダプタからの内部 bypass を物理的に不可能化)
status: resolved
category: bug
created: 2026-06-14T12:00:00+09:00
last_read:
open_entered: 2026-06-14T12:00:00+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-06T07:52:08+09:00
discard_reason:
pending_reason:
close_reason: ["done:DR-0027 (コア syntax gate + OpKvKey + reserved NS bouncer、commit 64b8315eed09)。kv.get の authsock NS 拒否 (DR-0018 §4.5 confidentiality 軸) は射程外で残タスク"]
blocked_by:
origin:
---

# コア公開 API レイヤで KEY / NS validation 強制 (= アダプタからの内部 bypass を物理的に不可能化)

- 記録: 2026-06-14 (kawaz 指摘の経緯: dogfood 復活直後の `zl4...` 鍵 regression 観察 → 「forget できない」現象 → 「NS 正規化」表層解 → **「コア API validation 欠落のアーキテクチャ違反」根本問題発見**)
- 関連: **DR-0003 (コアとアダプタの責務分離、本 issue の根本)** / DR-0017 (KV NS / KEY 文字種規定) / DR-0014 (kv definition model) / DR-0018 §4.5 (authsock NS 正規化、本 issue で具体化) / DR-0022 (failure_backoffs)

## 真の問題 (= アーキテクチャ違反)

DR-0003 は「コア (`cache-warden` lib) とアダプタ (`cache-warden-authsock` lib) の責務分離」を確立した。コアは秘密値の KV キャッシュ、アダプタはプロトコル変換。

DR-0017 §1.5 は KEY / NS の文字種を `[A-Za-z0-9_]+` に規定した。

**ところが、実装はこの 2 つを両立してない**:

- `crates/cache-warden-cli/src/commands/mod.rs:parse_kv_del` 等の CLI 入口に **だけ** `validate_cli_key` がある (= 外からは `:` 含むキーを reject)
- コア公開 API (`Store::define / set / get / delete` 等) は **キー引数を `String` で素通し受け取り、validation しない**
- = adapter は `Store` を直接呼ぶ経路で `:` 含むキーを push できる
- 実例: `crates/cache-warden-cli/src/daemon/authsock.rs:218 op_kv_key` が `format!("__authsock_op:{item_id}")` で `:` 含むキーを作り、`Store::define` にそのまま渡す (A-3a refactor で追加された経路)
- comment では「namespaced to avoid `[kv.*]` collisions」と書いてある = **DR-0017 規約を bypass するために命名で逃げてる typical anti-pattern**

= **「外からは入れない、内からは入れる」のアクセス制御階層の破綻**。コアとアダプタの責務分離が「実装で侵犯」されている。

`__authsock_op:zl4...` のような「内部キー」が CLI から touch できないのは表層の現象であり、真の問題は **コア API がキー命名規約を強制してない** こと。

## 私が当初考えた表層解 (= 不採用)

「NS 正規化で `authsock/op_<id>` にしましょう」(= 本 issue 旧版): これは確かに正しい方向だが、**構造的に再発を防いでない**:

- NS 正規化しただけだと、別の adapter が将来「内部キーは `__myauth_op:` 形式で…」と同じパターンを再生産する
- コア API が validation を持ってない限り、同じ規約違反は何度でも起きる

つまり、NS 正規化は **必要条件**だが **十分条件ではない**。

## 真の解

### 1. コア公開 API レイヤで KEY 命名規約を強制

**選択肢 (= 強い順)**:

#### 案 A: 型レベルで強制 (= 推奨、物理 bypass 不可能)

```rust
// crates/cache-warden/src/key.rs (新規)
pub struct StoreKey(String);  // private field、external 構築不可

impl StoreKey {
    /// `compose(ns, key)` か `parse(s)` 以外では作れない
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        validate_composed(s)?;  // = NS/KEY 規約 (DR-0017) を満たす
        Ok(Self(s.to_string()))
    }
    pub fn compose(ns: &Namespace, key: &Identifier) -> Self {
        Self(format!("{ns}/{key}"))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

// 公開 API の signature を変更
impl Store {
    pub fn define(&mut self, key: StoreKey, ...) -> ... { ... }
    pub fn set(&mut self, key: StoreKey, ...) -> ... { ... }
    pub fn get(&mut self, key: &StoreKey, ...) -> ... { ... }
    pub fn delete(&mut self, key: &StoreKey) -> ... { ... }
    // ...
}
```

- adapter は `StoreKey::parse(string)` か `StoreKey::compose(ns, key)` 経由でしかキー作成不可
- `String` を Store に直接 push する経路を **物理的に消す**
- bypass しようとすると Rust の private field アクセスが必要 (= reflection ない言語では unsafe + 内部実装依存、現実的に無理)

#### 案 B: 公開 API 内部で runtime validation

```rust
impl Store {
    pub fn define(&mut self, key: impl Into<String>, ...) -> Result<...> {
        let key = key.into();
        validate_composed(&key)?;  // ← API 内部で必ず呼ぶ
        ...
    }
}
```

- 型は String 受けるが、internal validation で守る
- 案 A より弱い (= struct 公開 field 直書きや、`Store::entries` の生 BTreeMap への外挿入経路があれば bypass される)
- ただし API surface は変えやすい

**推奨**: 案 A (= 型レベル)。cache-warden は **秘密値管理**という強い安全性要件のドメインなので、bypass 不可能性に投資する価値がある。

### 2. アダプタが API 経由でのみ操作する設計に揃える

A-3a 以降の authsock adapter は既に `Store::define / get_or_regenerate` 経由になってる (= 良い進歩)。本 issue で:

- `register_op_keys` の `store.define` 呼出を `StoreKey::compose(authsock_ns, op_id)` 経由に変更
- `op_kv_key` 関数を廃止 (= 生キー生成経路を消す)
- 同様に `Store::get / delete / pin` 等を呼ぶ全箇所で `StoreKey` 経由に統一

### 3. CLI 入口の validation は維持 (= 冗長な前段)

`validate_cli_key` は引き続き入れる:

- CLI 入口で早期 reject = error message が分かりやすい (= ユーザに「`:` は使えません」と伝える)
- 多層防御 = 万一コア API の validation が緩んでも CLI から bypass されない

`validate_cli_key` は **多層防御の前段** であり、**最後の砦ではない**。

### 4. authsock NS 予約 (= DR-0018 §4.5 の最小実装)

内部鍵は `StoreKey::compose(Namespace::authsock(), Identifier::parse(format!("op_{item_id}"))?)` で作る。`authsock` NS は user の `kv define / set` から block (= reserved NS bouncer)。

これは DR-0018 §4.5 の既存計画に沿う。kv インターフェースに対する特殊 dispatch は **不要** (= ns 分離で目的達成、kawaz 指摘の「kv に対する特殊なことは必要ない」)。

## 実装スコープ

中規模 (= 案 A 採用で 300-500 SLOC + テスト + 全 store 利用箇所の更新):

1. **`crates/cache-warden/src/key.rs` 新規**: `StoreKey` newtype + `compose` / `parse` メソッド + validation
2. **`Store` 公開 API の signature 変更**: `define / set / get / delete / regenerate / get_or_regenerate / pin / unpin / state_of / failure_backoff_remaining` 全部 `StoreKey` 受けるように
3. **既存 `String` キー利用箇所の修正**:
   - `crates/cache-warden-cli/src/daemon/handler.rs` (= control socket handler、`KvGet / KvSet / KvDel` 等の wire request からの key 抽出 → `StoreKey::parse`)
   - `crates/cache-warden-cli/src/daemon/authsock.rs:218 op_kv_key` 廃止、`register_op_keys` で `StoreKey::compose(authsock, op_<id>)`
4. **`authsock` reserved NS の bouncer**: `kv.define / set` で `authsock` NS を reject
5. **テスト**:
   - `StoreKey::parse` の正常 / 異常系
   - `Store::define` に `String` 渡し不可な型レベル保証 (= compile-time check)
   - authsock adapter が `__authsock_op:` 形式を作れないことを確認 (= grep でも OK)
   - reserved NS bouncer の wire レベルテスト
6. **既存テスト更新**: 全部の `Store` 利用テストで `StoreKey` 経由に変更
7. **doc 更新**: DR-0017 / DR-0018 §4.5 / DESIGN.md / STRUCTURE.md

## DR 化候補

本 issue は **アーキテクチャ違反の是正**で DR 級判断:

- DR-0017 改訂 or 新規 DR (= DR-0024 候補): 「コア公開 API レイヤで KEY 命名規約を強制、`StoreKey` newtype 導入」
- 実装着手前に DR 起票が筋

## 反省記録 (= 4 ラウンドの誤り)

本 issue は当初 4 ラウンドの誤り経て本形に至った (2026-06-14):

1. **1 ラウンド目**: 専用 `internal forget` CLI コマンド + 案 Z (= 何もしない) のトレードオフ → kawaz「トレードオフじゃない、別軸」(memory `feedback-security-dimensions-not-tradeoff`)
2. **2 ラウンド目**: value-type `op-ssh-key` 派生ビュー + dimension 別アクセス制御 → kawaz「forget は既存 `kv del` でしょ」(memory `feedback-check-existing-api-before-proposing-new`)
3. **3 ラウンド目**: NS 正規化のみ + dimension 別アクセス制御は残す → kawaz「kv に対する特殊なことは不要、ns 必須化して専用 ns に入れるだけ」
4. **4 ラウンド目**: NS 正規化 + reserved NS bouncer → kawaz「**コアとアダプタを分けて責務分離してるのに実装で勝手に内部で違反キーで直接ストア保存してたら意味ないだろ**」「**コアとはアダプタへ公開する API を適切に設計してアダプタ間など責務分離されている所ではインターフェース経由でしか操作すべきでない**」
5. **本形**: コア公開 API レイヤで KEY validation 強制 (= `StoreKey` newtype) + adapter は API 経由のみで操作 + NS 正規化と reserved NS bouncer はその上に乗る

**教訓**: アーキテクチャ違反は「現象 (= forget できない)」から始まる、表層解 (= NS 正規化) では再発するので **公開 API の契約**として validation を強制する。memory `feedback-core-api-validation-not-cli-edge`。

加えて、kawaz が冒頭で「コードも把握して」と言ったのは **まさにこのアーキテクチャ違反を最初に発見させたかったから** (`crates/cache-warden/src/store.rs` の API signature を Read すれば `String` を素通しで受けてるのが 5 秒で分かる、`crates/cache-warden-cli/src/daemon/authsock.rs:218` で `:` 含むキーを Store に push してるのも 5 秒で分かる)。memory `feedback-session-init-deep-code-read`。

## 実装結果 (2026-07-06) — 案 A → 案 B に改訂して実装

上記「真の解」の案 A (= コアに `StoreKey` newtype を導入し型レベル強制) は、確定フィードバック
「**ドメイン型はアダプタに置き、コアは generic に保つ**」(memory `feedback-domain-types-in-adapters-not-core`)
と食い違う。コアに authsock 固有のキー形状を教えるのは責務分離の逆方向の侵犯になるため、**案 B**
(= コアに generic な runtime 文字種ゲート + アダプタにドメイン型) で実装した。判断の正本は
[DR-0027](../decisions/DR-0027-core-key-syntax-gate.md)。

実装内容:

1. **コア generic syntax gate**: `crates/cache-warden/src/key.rs` に `validate_key_syntax`
   (`[A-Za-z0-9_]+` が `/` 区切りで 1 or 2 セグメント) + `InvalidKey` を新設。`Store::set` /
   `define` / `define_with_meta` の頭で強制 (`set` は cap → key syntax の順で DR-0024 を維持)。
   `set` の戻り値を `Result<(), SetError>` に、`DefineError::InvalidKey` を追加。
   **コアは syntax のみ、NS semantics はアダプタ責務** (コアが 1 or 2 セグメント両方許すのは
   generic KV の性質。wire は `NS/KEY` を要求し続ける)。
2. **authsock ドメイン型**: `op_kv_key` 関数を廃止し `OpKvKey` 型 (`authsock/op_<item_id>`、
   item_id 英数字 validate、非適合は skip) に置換。DR-0026 fallback 経路も同じ `OpKvKey::new` を通る。
3. **reserved NS bouncer**: `authsock` NS への `kv.set` / `kv.define` を wire
   (`reject_reserved_namespace_write`、最後の砦) + CLI (`reject_reserved_write_namespace`、前段) で拒否。
4. **旧形式の永続化検証**: `__authsock_op:` (旧) も `authsock/op_*` (新) も `store.define`
   (空 source_meta) で登録され、`snapshot_definitions` が空 source_meta を skip するため **disk に
   到達しない** (メモリのみ、daemon 再起動で消える)。regression test
   (`snapshot_excludes_authsock_op_definitions_never_persisting_them`) で guard。移行レイヤ不要。

残タスク: `authsock` NS の `kv.get` 拒否 (confidentiality 軸、DR-0018 §4.5) は本実装の射程外。
CLI 入口の validation (`validate_cli_key`) は多層防御の前段として維持済み。

## 関連

- `crates/cache-warden/src/store.rs` (= 公開 API、set/define/define_with_meta で文法強制)
- `crates/cache-warden/src/key.rs` (= 新規、`validate_key_syntax` + `InvalidKey`。案 B のため newtype ではなく runtime 検証)
- `crates/cache-warden-cli/src/namespace.rs` (= `validate_identifier` 等の既存 validation、多層防御の前段として維持)
- `crates/cache-warden-cli/src/daemon/authsock.rs` (= `op_kv_key` 関数廃止、`OpKvKey` ドメイン型に置換)
- `crates/cache-warden-cli/src/daemon/handler.rs` (= wire の reserved NS bouncer `reject_reserved_namespace_write`)
- `crates/cache-warden-cli/src/commands/mod.rs validate_cli_key` (= 維持、多層防御の前段。`reject_reserved_write_namespace` 追加)
- **DR-0003** (= コアとアダプタの責務分離、本 issue で実装の整合性を担保)
- DR-0017 (= 文字種規定、本 issue で型レベル強制に格上げ)
- DR-0018 §4.5 (= authsock NS 正規化、本 issue 内で完了)
- DR-0014 / DR-0022 (= del セマンティクス、変更不要)
- 関連 memory: `feedback-core-api-validation-not-cli-edge` / `feedback-session-init-deep-code-read` / `feedback-check-existing-api-before-proposing-new` / `feedback-security-dimensions-not-tradeoff`
- 関連 issue [2026-06-14-op-refetch-loop.md](./archive/2026-06-14-op-refetch-loop.md) (= `zl4...` regression 観察起点、close 済み)
