---
title: kv get peer-identity guard
status: open
category: design
created: 2026-06-22T21:18:58+09:00
last_read:
open_entered: 2026-06-22T21:18:58+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by: [2026-06-22-crate-macos-process-inspect]
origin: 自リポ TODO
---

# kv get peer-identity guard

## 概要

cache-warden の `kv set` 時に **peer-identity constraint** を declarative に付与し、`kv get` 時にそれを評価して認可する。1Password の "白紙委任" を超え、kv consumer が「自分が set した secret を、自分の信頼境界内のプロセスにだけ exposing する」コントロールを得る。

## 背景

なぜ必要か、どこから来た要望か: 2026-06-22 セッション、cw の差別化機能ブレストから発生。

## 想定 constraint カテゴリ

set 時に以下のような述語を 1 つ以上付与可能:

- **同 SHELL ガード**: set 元プロセスの祖先チェーンに該当する shell プロセスを記録し、get 時の peer も同じ shell 祖先を持つことを要求 (= 同 SHELL セッションから OK、別 SHELL / 別プログラムは NG)
- **同祖先ガード**: 任意の祖先 (e.g. 特定 IDE プロセス) を共有要求
- **同ユーザガード**: peer uid が set 元 uid と一致 (= 既定で自動付与しても良い)
- **特定 codesign 署名**: peer の code signature の identifier / team identifier が一致 (= 詐称しにくい強い識別子)
- **特定コマンド名 / フルパス**: peer の `proc_pidpath` 等で identify (= 詐称可能だがカジュアル用途に便利、明示的に「弱い識別」と doc 化)
- **特定 env**: peer の env vars 一致 (= 特定 marker env を持つプロセスにだけ exposing)

## API イメージ (CLI / config 両面)

CLI:
```
cw kv set FOO BAR \
  --require-same-shell \
  --require-same-user \
  --require-signed-by=org.example.tool
```

config (= 既定 policy):
```toml
[kv.policy]
default_require_same_user = true
```

## 設計検討ポイント

- constraint storage: kv entry frontmatter (= set 時固定) vs 別 store
- snapshot fields: 何を pin して比較するか (= unique pid vs codesign identifier vs cmdline)
- 評価エラー時の挙動: 拒否 (= 安全側) を default、verbose mode で reason 提示
- DR-0022 既存の `[auth].command` (CommandAuthenticator) との関係: 同居 / 統合 / 置換のどれか
- 不可逆性: 弱い識別 (cmdline) と強い識別 (codesign) をユーザに明示する UX

## 受け入れ条件

- [ ] `kv set` 時に peer-identity constraint を付与できる (CLI フラグ + config 両面)
- [ ] `kv get` 時に constraint を評価し、不一致なら拒否する
- [ ] 弱い識別 (cmdline) と強い識別 (codesign) をドキュメントで明示している
- [ ] `[auth].command` (CommandAuthenticator) との関係が設計 DR に記録されている
