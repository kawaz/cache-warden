# DR-0027: コア公開 API での合成キー文法（syntax）強制と authsock 内部鍵の予約 NS 正規化

- Status: Accepted
- Date: 2026-07-06

## Context

DR-0003 はコア（`cache-warden` lib）とアダプタ（`cache-warden-cli` / `cache-warden-authsock`）の
責務分離を確立し、DR-0017 §1.5 は KEY / NS の文字種を `[A-Za-z0-9_]+` に規定した。しかし、
この文字種強制は **CLI / wire 境界にしか存在しなかった**（`validate_cli_key` /
`validate_protocol_key`）。コアの公開 API（`Store::set` / `define` / `define_with_meta`）は
キーを `String` で素通し受けし、検証していなかった。

結果、同一プロセス内のアダプタは Store を直接呼ぶ経路で規約違反キーを push できた。実例は
authsock の `op_kv_key(item_id) = format!("__authsock_op:{item_id}")`（`:` = DR-0017 文字種外）を
`Store::define` に無検証挿入していた経路。「外からは入れない、内からは入れる」というアクセス制御
階層の破綻であり、コアとアダプタの責務分離が実装で侵犯されていた（issue
`2026-06-14-internal-key-forget-interface.md`）。

当初 issue は案 A（コアに `StoreKey` newtype を導入し型レベルで強制）を推していたが、これは
「ドメイン型はアダプタに置き、コアは generic に保つ」という確定フィードバックと食い違う
（各アダプタが自分のドメイン鍵形式 + `Display` で正規シリアライズ責務を完結すべきで、コアに
authsock 固有のキー形状を教えるのは逆方向の侵犯）。よって案 B を採る。

## Decision

### 1. コアは合成キーの**文法（syntax）**を全書込入口で強制する

`crates/cache-warden/src/key.rs` に generic な runtime 検証を置く:

- `validate_key_syntax(key)`: `[A-Za-z0-9_]+` のセグメントが `/` 区切りで **1 個または 2 個**
  （= `KEY` or `NS/KEY`）であることを検証。空文字 / `:` / 空白 / 制御文字 / `.` / `-` /
  先頭末尾 `/` / 多重 `/` / 3 セグメント以上を reject。
- `InvalidKey` エラー型（違反キー文字列を保持。キーは名前であって秘密値ではないので echo 可）。
- `Store::set` / `define` / `define_with_meta` の頭でこれを呼ぶ。`set` は cap 検証を先に行い
  （DR-0024: cap 拒否は observable state を一切触らない原則を維持）、その後に文法検証。`define`
  系は cap 対象外（value-free metadata、DR-0024）なので文法検証が唯一かつ最初の鍵ゲート。
- エラー型: `set` は `Result<(), SetError>`（`InvalidKey` / `CapMismatch`）、`define` 系は
  `DefineError::InvalidKey` を追加。

Store の 3 つの内部マップは全て private で、新規挿入入口は `set` / `define` / `define_with_meta`
の 3 つのみ。この 3 つを塞げば、コア crate 外からの bypass は物理的に不可能になる。

### 2. syntax は強制するが semantics は解釈しない（責務分離の要）

コアは DR-0017 が定める**合成キー文法**（文字種 + 1/2 セグメント形状）だけを強制する。
NS の**意味論**（どの NS が予約か、bare KEY を許すか）は解釈しない。それはアダプタ層の責務。

- コアが **1 or 2 セグメント**の両方を許すのは意図的: コアは generic KV であり、自身のテストは
  bare identifier（`"K"` / `"GITHUB_KEY"`）でキーを張る。一方 daemon アダプタは外部到達可能な
  全キーを `NS/KEY` に合成する（wire の `validate_protocol_key` は完全な `NS/KEY` を要求し続ける）。
- 予約 NS の拒否も semantics なのでアダプタ層（§4）。

### 3. アダプタはドメイン型で自分のキー形式を閉じる

authsock の `op_kv_key` 関数（生キー文字列生成）を廃止し、ドメイン型 `OpKvKey` に置き換える:

- `OpKvKey::new(item_id) -> Option<Self>`: item_id が英数字のときだけ
  `authsock/op_<item_id>` を合成（op item id は英数字。非英数字 = op から観測されない = None で
  skip し、`store.define` 深部での hard error でなく「鍵 1 個の skip」に縮退）。
- 正規シリアライズ責務はアダプタ内に閉じ、コアは authsock のキー形状を知らないまま。
- DR-0026 の fallback 経路（`DiscoveryOutcome::Stale` → `discover_all_sources` →
  `register_op_keys`）も同じ `OpKvKey::new` を通るので、キー生成経路は一本化される。

### 4. authsock 内部鍵の予約 NS 正規化と reserved NS bouncer（DR-0018 §4.5）

- 内部鍵は `__authsock_op:<item_id>`（文字種外の擬似 prefix）を廃止し、予約 NS `authsock` の
  正規キー `authsock/op_<item_id>` に移す。DR-0017 の機構に統合され、内部特例が消える。
- `authsock` NS への user 書込（`kv.set` / `kv.define`）を **reject**（reserved NS bouncer）:
  - wire 入口（control socket handler の set/define）: `validate_protocol_key` 通過後に
    `reject_reserved_namespace_write` で `authsock` NS を拒否（= 最後の砦、raw request も捕まえる）。
  - CLI 入口（`parse_kv_set` / `parse_kv_define`）: `reject_reserved_write_namespace` で早期・親切に
    拒否（= 前段、defs 経由の登録も最終的に wire を通るので wire bouncer が包括する）。
- 本 DR の射程は **write path の bouncer** のみ。`authsock` NS の `kv.get` 拒否（confidentiality
  軸、DR-0018 §4.5）は別軸で、本 DR では扱わない（残タスク）。

### 5. 旧 `__authsock_op:` 形式は永続化されない（メモリのみ）

`register_op_keys` は `store.define`（source_meta なし = `SourceMeta::new()`）で登録する。
`snapshot_definitions` は `SourceSpecWire::from_source_meta` が `None`（空 source_meta）を返す
定義を skip するため、旧形式も新形式も **disk に到達しない**（daemon 再起動で消える）。
移行レイヤは不要。これは regression test で guard 済み。

## Alternatives Considered

- **案 A: コアに `StoreKey` newtype（型レベル強制）**
  - 不採用理由: 「ドメイン型はアダプタに置く」確定フィードバックと食い違う。コアに authsock 固有の
    キー形状を教えることになり、責務分離を逆方向に侵犯する。runtime gate + アダプタのドメイン型
    （案 B）で「物理 bypass 不可能」と「コア generic 維持」を両立できる。
- **コアが `NS/KEY`（2 セグメント必須）を強制**
  - 不採用理由: コアは generic KV で、自身のテストは bare identifier を使う。NS 必須は NS
    semantics であってアダプタの責務。コアを 2 セグメント必須にすると全コアテストが壊れ、かつ
    generic KV の性質を裏切る。
- **NS 正規化のみ（bouncer / コア強制なし）**
  - 不採用理由: 別アダプタが将来同じ「内部キーは `__myauth_op:` 形式で…」パターンを再生産する。
    コア API が validation を持たない限り規約違反は何度でも起きる（issue の当初表層解）。

## Consequences

- breaking（pre-1.0、移行レイヤなし）: `Store::set` の戻り値が `Result<(), CapError>` から
  `Result<(), SetError>` に、`DefineError` に `InvalidKey` variant が増える。ライブラリ利用者の
  エラーハンドリングに影響。
- breaking: authsock 内部鍵の表示名が `__authsock_op:*` → `authsock/op_*` に変わる（status /
  list の表示のみ、外部契約ではない）。
- `authsock` NS への `kv.set` / `kv.define` が拒否される（新しい失敗ケース）。
- コア公開 API が「合成キー文法」を契約として強制するようになり、in-process アダプタからの
  規約違反キー挿入が構造的に不可能になった。

## 関連

- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — コアとアダプタの責務分離（本 DR で実装整合性を担保）
- [DR-0017](./DR-0017-kv-namespaces.md) — KEY / NS 文字種規定（本 DR でコア API に強制を格上げ）
- [DR-0018](./DR-0018-typed-sources-auth-and-prefetch.md) — §4.5 authsock 内部鍵の予約 NS 正規化（本 DR で write bouncer を実装、get 拒否は残タスク）
- [DR-0024](./DR-0024-cap-access-gate.md) — capability gate（本 DR は cap → key syntax の順序を維持、§Consequences の follow-up を実装）
- issue `2026-06-14-internal-key-forget-interface.md` — 本 DR の起点（案 A → 案 B 改訂）
