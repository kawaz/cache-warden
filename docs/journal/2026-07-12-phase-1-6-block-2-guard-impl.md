# Phase 1.6 Block 2: DR-0030 guard の core/snapshot/evaluator/CLI 実装

draft-DR-0030 の per-entry peer-identity guard を land (commit `e9f417d3`)。
handler 統合と config `[kv.policy]` は Open Q1 (`default-require-same-user` の
既定値) の kawaz 裁定待ちとして次ブロックへ切り離した。

## ワークフロー構成

opus47-worker で実装 → sonnet5-worker-low で機能検証 + Fable (メインセッションの
tier) でセキュリティレビューを並列実行 → 指摘をメインセッションで修正 → 確認レビュー。
「本気の意味論レビュー」を最上位 tier に置き、機械的な検証は中位 tier に振る分担。

## ハマり所と発見経緯 (セキュリティレビュー起点)

### HIGH-1: mixed-version silent no-op (handler 未統合 × wire 追加の組合せ)

CLI に 4 つの `--require-*` flag を先に生やし、`Request::KvSet.guard_constraints`
を wire に追加したが、`handle_set` 側の `set_guard` 呼び出しは Open Q1 待ちで
未着手というブロック構成にした。素朴にこの状態で通すと:

```
$ cw kv set FOO BAR --require-same-user --require-same-shell
# CLI は "guard 宣言込みで set した" つもりで exit 0
# daemon は guard_constraints を読み捨てて無条件に値を保存
# → 実際には無防備な entry ができる。呼び出し側の期待と実体が乖離
```

宣言と実体が乖離する窓は「CLI が動く」「daemon が受理する」の両方が green に
見えるため、テストを書かないと気付かない類の穴だった。

**発見**: Fable のセキュリティレビューで「handler 未統合の間、宣言済み
constraint はどこへ行くのか」を問われて可視化。

**解決**: `handle_set` の reserved-namespace gate 直後に、`guard_constraints`
非空なら `BadRequest` で即座に拒否する分岐を追加 (`handler.rs`)。「宣言したのに
黙って無視される」ではなく「宣言したら統合完了まで拒否される」に倒す。統合後に
1 行 diff で消える設計であることをコード内コメントに明記し、テストも 2 本追加
(`set_with_wire_declared_guard_constraints_is_rejected_fail_closed` /
`set_with_empty_guard_constraints_still_succeeds`)。

### HIGH-2: pid 再利用 + start_time 取得失敗の組合せで fail-open に縮退

実体 pin の照合ロジックの初期実装は、`unique_id` (macOS 限定の private API 由来、
取得失敗があり得る) が両側で取得できない場合、`start_time` 比較にフォールバック
する設計だった。ここで **`start_time` 自体も両側 `None` になるケース** (crate の
`ancestry` 取得が一部失敗する等) を辿ると、フォールバック先が消失して
**name-only 比較まで縮退**しかねない実装になっていた。

pid は OS によって再利用されるため、name のみの比較は「pid が再利用された別の
無関係プロセス」を実体一致と誤認しうる。これは DR-0030 本文の fail-closed 原則
(§Security considerations) に反する縮退だった。

**発見**: レビューでの疑問形は「(None, None) になったら何が起きるか」の
明示的なマトリクス確認 (取得可否 2 軸 × 両側の全組合せを埋める追及)。

**解決**: 照合優先順位を「unique_id 両側あり → unique_id / 片側のみ →
start_time / 両方 None → **deny**」に固定。name-only 縮退の経路自体を削除した。

### HIGH-3: μs→ms 切り捨てと厳密等値比較の組合せで restart 後の pin 照合が全滅

snapshot export 時に pin の `start_time` を ms 精度で保存していた。evaluator 側の
照合は `PinnedProcess::start_time == getter_side_start_time` の厳密等値比較なので、
restart で snapshot から実体を復元した pin と、OS から新たに取得した getter 側の
start_time (実体は μs や ns 精度で取得される) が**丸め誤差で一致しなくなる**。
結果として **restart のたびに全ての same-ancestor / same-shell guard が
「実体が変わった」と誤判定されて deny になる** (= guard が実質的に機能しなく
なる、fail-closed 方向の壊れ方だが運用上は「guard 付き entry が restart 後に
一切読めなくなる」という別の実害)。

**発見**: セキュリティレビューが inspect.rs の取得精度 (`from_secs + from_micros`
= μs) と snapshot 側の `as_millis` 切り捨てを突き合わせて指摘。単体の round-trip
テストでは「ms 精度同士の比較」で通ってしまい、live 側 (μs) と復元側 (ms) が
混ざる restart 経路でしか露呈しない。

**解決**: `SnapshotGuard` の pin フィールドを `start_time_us` (μs 精度) に変更。
本ブロックで `FORMAT_VERSION` を条件付きで +1 する wire v2 を新設している最中
だったため、**精度を上げる修正コストが最も安いタイミング**だった (v2 を出した
後に精度を上げ直すと再度 version bump が必要になる)。

## 設定値・コマンド

CLI flag (v1 スコープ、`kv set` のみ):

```bash
cw kv set FOO BAR --require-same-user --require-same-shell
cw kv set FOO BAR --require-same-ancestor=code --require-command=git
```

検証コマンド:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace   # 1210 tests green (unit のみ)
```

## 議論の要点

- **same-shell を独立 constraint にしなかった判断**: `same-shell` は
  `SameAncestor` の evaluator ロジックと完全に同一 (「pin された実体が getter
  chain に居るか」)。差は「どの実体を pin するか」の**選び方**だけなので、
  `DeclaredAncestor::SameShell` タグを乗せて表示だけ分岐させる形に集約した。
  独立 variant にすると評価コードが 2 経路に分岐し、後から「同じロジックなのに
  実装が 2 箇所ある」状態になるリスクがあった
- **unknown wire kind の deserialize エラー化**: 「将来 constraint 種別が
  増えたとき、旧 daemon が新 CLI の宣言を受け取ったらどうなるか」の議論から、
  silently drop (= 宣言の一部が消えたまま set が成功する) ではなく fail-loud
  (deserialize エラーで set 自体が失敗する) を選んだ。DR-0030 の他の判断
  (unknown field は unsafe 側に倒さない) と整合させるため
- **handler 統合を切り離した理由**: Open Q1 (`default-require-same-user` の
  既定値) は「guard なし set の互換性」に直結する裁定で、先に統合すると
  裁定後に配線をやり直すコストが発生する。core/snapshot/evaluator/CLI の型を
  先に固めて、統合は 1 ブロック分の作業として独立させる方が back-and-forth が
  少ないという判断

## 未検証事項・持ち越し

- handler 統合は完了 (commit `429fbd03`)
- authsock SIGN 経路が guard を一切評価しない未規定の穴が新規 open。issue
  `2026-07-12-authsock-sign-dr0030-guard-scope` で裁定待ち
- `--require-cwd` と recent-input 系の constraint 拡張の議論が進行中
- TouchID 実機 e2e (Block 3) が残る

## 検証

`cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` /
`cargo test --workspace` すべて green (1210 tests)。TouchID を伴う実機 e2e は
handler 統合後に別ブロックで実施予定。

## handler 統合 (同日追記)

commit `429fbd03` で handler 統合を完了。`plan_guard_record` / positive ack /
config `[kv-policy]` / kv list 表示を実装、`cargo test --workspace` 1233 tests
green。詳細は draft-DR-0030 の「handler 統合記録 (2026-07-12)」節を参照。

ハマり所: `[kv.policy]` は TOML の `[kv.NAME]` 定義 map と衝突して startup
エラーになるため `[kv-policy]` に改名した (fail-loud なので事故には至らないが
DR 表記と食い違っていた)。
