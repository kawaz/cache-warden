---
title: DR-0030 guard に --require-cwd=PATH constraint を追加 (direnv 的区画化)
status: open
category: task
created: 2026-07-12T15:41:13+09:00
last_read:
open_entered: 2026-07-12T15:41:13+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# DR-0030 guard に --require-cwd=PATH constraint を追加 (direnv 的区画化)

## 概要

draft-DR-0030 (kv per-entry peer-identity guard) の constraint モデルに、
**cwd ベースの区画化**を表現する `--require-cwd=PATH` constraint を追加する。
direnv 的な「このディレクトリ配下から実行された時だけ通す」使い方を想定した、
カジュアルな制限として位置づける。

kawaz 提案 (2026-07-12)。

## 背景

現行の draft-DR-0030 §1 の constraint モデルは `same-user` / `same-ancestor`
(same-shell sugar 含む) / `command` の 3 種 (v1) + phase 2 の `signed-by` /
`env-marker`。ここに **getter 自身の cwd** を判定材料にする軸が無く、
「特定ディレクトリ配下で作業している時だけ読める」という direnv ライクな
区画化を宣言できない。

## 仕様方針 (kawaz 提示)

1. **識別強度**: `command=` よりさらに弱い weak ラベル (`chdir` 一発で満たせる)。
   help / doc / dialog の全箇所で「weak (casual)」と明示する
   (draft-DR-0030 §1b の脅威モデル表と同じ形式で「防げる / 防げない」を記載)
2. **照合対象**: getter chain **先頭 (requester 自身)** の cwd。祖先ではなく
   直接の呼び出し元プロセス
3. **path 正規化**: symlink 解決、`/tmp` → `/private/tmp` (macOS)、末尾スラッシュ
   の除去が必要。**記録時 (set 時) と照合時 (get 時) で同じ正規化関数を通す**
   ことが必須 (片方だけ正規化すると誤判定・すり抜けの原因になる)
4. **取得手段**: `proc_pidvnodepathinfo` (macOS)。crate `macos-process-inspect`
   に cwd 取得 API の追加が必要。非 macOS は評価不能 = fail-closed
   (draft-DR-0030 §4 の既存 fail-closed 原則と整合)
5. **CLI**: `--require-cwd=PATH` (`$PWD` 等の展開は shell 側が行う、cache-warden
   側は展開後の文字列を受け取るだけ)

### constraint 強度順序 (doc/help/表示の統一)

既存 constraint と合わせた強度順 (強い→弱い):

```
same-ancestor / same-shell > signed-by (phase 2) > same-user > command > cwd
```

この順序を doc・`--help`・`kv list` 表示・(将来の) dialog 表示の全箇所で
統一する (draft-DR-0030 §1b が「弱い識別の明示」を issue 受け入れ条件に
掲げているのと同じ思想を cwd にも適用)。

## 着手タイミング

draft-DR-0030 の handler 統合 (Block 2 後段、`docs/decisions/draft-DR-0030-kv-peer-identity-guard.md`
の「handler 統合時の TODO (Block 3 以降)」節) が完了した後の**追加ブロック**として
着手する。Block 2 / Block 3 のスコープには含めない。

## 受け入れ条件

- [ ] `macos-process-inspect` crate に peer の cwd 取得 API (`proc_pidvnodepathinfo`
      ベース) が追加されている
- [ ] `GuardConstraint` に `Cwd { path: PathBuf }` (仮称) が core (`crates/cache-warden/src/guard.rs`)
      に追加され、record は plain data のまま (core 非解釈原則を維持)
- [ ] evaluator (`crates/cache-warden-cli/src/daemon/guard.rs`) に cwd 照合ロジックが
      追加され、set 時記録 / get 時照合の両方で同一の path 正規化関数を通す
- [ ] 非 macOS では cwd constraint の評価が fail-closed (拒否) になる
- [ ] `--require-cwd=PATH` が `kv set` に追加され、help / completion
      (`completions/_cache-warden`) が同期している
- [ ] `--help` / doc / `kv list` 表示に cwd constraint の weak ラベルと
      強度順序 (same-ancestor/same-shell > signed-by > same-user > command > cwd) が
      一貫して表示される
- [ ] draft-DR-0030 本文 (§1 constraint モデル表、§1b 脅威モデル表) に
      cwd constraint の行が追加されている

## TODO

- [ ] draft-DR-0030 の handler 統合 (Block 3 以降) 完了を確認してから着手する
- [ ] `macos-process-inspect` への cwd API 追加方針を crate 側 issue
      (`2026-06-22-crate-macos-process-inspect` 系譜) と整合させる
