---
title: top-level --socket が実際にはサブコマンド後にしか置けない (doc/impl 乖離)
status: resolved
category: bug
created: 2026-07-13T17:54:24+09:00
last_read: 2026-08-11T23:47:53+09:00
open_entered: 2026-07-13T17:54:24+09:00
wip_entered: 2026-08-11T23:59:00+09:00
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-08-12T00:48:55+09:00
discard_reason:
pending_reason:
close_reason: ["dr/DR-0002","implemented","done:commit 541ff256, clap 4 (builder) 置換で修正案(c)実装。動機バグ2件 (先頭--socket位置 / ハイフン始まりVALUE) 実機解消確認、既存テスト無改変で1277 passed、completion 15/15 PASS、fable MEDIUM指摘 (argv順反転) 対応済み"]
blocked_by:
origin: Block 3b e2e 検証中の kawaz 指摘 (2026-07-13)
---

# top-level --socket が実際にはサブコマンド後にしか置けない (doc/impl 乖離)

## 概要

top-level `--socket` オプションは doc コメント上「tail のどこに置いても良い」
とされているが、実装では command dispatch (`args[0]` を command として先に
取り出す処理) が `take_socket_flag` の呼び出しより先に走るため、
`cache-warden --socket PATH kv get FOO` のようにサブコマンドより前に置くと
`unknown command: --socket` で reject される。

## 背景

2026-07-13 Block 3b の e2e 検証中に kawaz が発見。

- `crates/cache-warden-cli/src/commands/mod.rs:160-192` の `take_socket_flag`
  doc コメントは「Extract `--socket PATH` ... anywhere in the tail」を明言
- `crates/cache-warden-cli/src/main.rs:301` 付近のコメントも
  「Resolve `--socket` (anywhere in the tail) once」と書いている

しかし実装は `main.rs:279-280` で

```rust
let command = args[0].clone();
let tail = &args[1..];
```

のように `args[0]` を command として先に取り出しており、`take_socket_flag`
の呼び出し (main.rs:301 付近) はその後にしか来ない。このため `--socket` が
`args[0]` の位置にあると command 名として誤解釈され、command dispatch で
reject される。(2026-07-13 実機コード確認済み: 上記行番号・実装とも現状一致)

実運用上のワークアラウンド (現状動く形): `cache-warden kv --socket PATH get FOO`
のように、サブコマンドの直後に置けば `take_socket_flag` が正しく拾う。

関連: DR-0010 (socket 解決の優先順位: CLI `--socket` > config `[daemon].socket`
> built-in default)。本 issue は優先順位そのものではなく、CLI 上で
`--socket` を置ける位置が doc と実装で乖離している点が対象。

## 受け入れ条件

- [ ] 修正方針を (a) / (b) / (c) のいずれかで決定する
  - (a) `main.rs` の command dispatch より前に `--socket` を tail 全体から
        (位置に関わらず) strip する — グローバル option を先頭に置ける方が
        慣習的で `take_socket_flag` の doc 記述とも一致する。暫定対応として
        実施しても良いが、本命は (c)
  - (b) doc / help 文言を実装に合わせ「サブコマンドの後にのみ置ける」と訂正する
  - (c) clap 等のまともな CLI パーサに置き換える (kawaz 提案 2026-07-13、推奨)。
        現行の手書き dispatch (main.rs の args[0]/tail 二分 + 各 dispatch_* の
        while ループ + 独自 help renderer + 手書き completion) は本 issue の
        根本原因で、同種の doc/impl 乖離 (グローバル option の順序・複数指定
        可否・`kv set` の `--require-*` との相互作用・`--help` 出力の網羅性) が
        今後も出続ける。clap (derive) 導入で: グローバル option 定義がどこに
        でも書ける (subcommand の前後不問)、`--help` 生成が定義から自動、
        completion (bash/zsh/fish/powershell) が自動生成、`--` セパレータ /
        bool フラグ / repeat フラグ の慣習実装が組み込みになる。CLAUDE 常時
        rule `cli-design-preferences` の要件 (サブコマンドネスト / `--help`
        セクション分け / ロングオプション基本 / `--no-xxx` 反転 / `--` セパ
        レータ / 補完) を確認しつつ、clap 4 が全要件を満たすか比較検証してから
        採用判断すること。既存 CLI 使い方 (`kv set --require-*`、
        `daemon register --label` 等) を破壊しない形での段階移行が必要
        (トップレベル → daemon → kv の順で移す等)。作業量は数百行の削除 +
        clap 定義の再構築で大きいが、テストが 1963 件揃っているので回帰
        リスクは制御可能
- [ ] `cache-warden --socket PATH kv get FOO` (先頭指定) と
      `cache-warden kv --socket PATH get FOO` (サブコマンド後指定) が
      同一に動作する (または doc 通りサブコマンド後のみ動作する) ことを確認
- [ ] `take_socket_flag` の doc コメントと `main.rs` 側のコメントが実装と
      一致していることを確認

## 追加実機サンプル (2026-08-11、Block 3b Item 2 準備中)

`kv set --namespace test --require-same-shell sshkey "<PEM>"` のように VALUE
位置引数が `-----BEGIN OPENSSH PRIVATE KEY-----` で始まると、手書きパーサが
`--` 始まりトークンをオプションと誤認して reject する。回避は `--` セパレータ
(`... --require-same-shell -- sshkey "<PEM>"`)。clap 置換 (推奨案 c) なら
`allow_hyphen_values` 相当で自然に解決する系の症状であり、置換動機の追加材料。

## TODO

<!-- wip 時のみ -->

- 修正方針は (c) clap 置換で確定 (kawaz 裁定済み推奨案)。codex worker で実装着手 (2026-08-11)。
