---
title: graceful restart holder の非 panic 規律の regression 保護 (panic=abort follow-up)
status: idea
category: design
created: 2026-07-09T23:44:04+09:00
last_read:
open_entered:
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:    # 1-line JSON array string[] 例: ["discarded","環境が変わった"]
pending_reason:    # 1-line JSON array string[] 例: ["pending","v2 待ち"]
close_reason:      # close 時に update が記録。1-line JSON array string[] 例: ["dr/DR-0007","implemented"]
blocked_by:
origin: DR-0029 bundle 2 adversarial review LOW への follow-up
---

# graceful restart holder の非 panic 規律の regression 保護 (panic=abort follow-up)

## 背景

DR-0029 bundle 2 の adversarial review LOW で提案された `[profile.release] panic = "abort"` は、cache-warden 全体で「1 request panic → daemon 全体 abort」の副作用が実運用リスクとして過大と判断し **revert** (Cargo.toml のコメントに経緯記載、change zlwxovoo)。

holder コード (`crates/cache-warden-cli/src/daemon/graceful_restart/handoff.rs::holder_child_main` と関連 helper) の非 panic 規律は現状 code review で担保しているが、regression 保護の仕組みが欠けている。

## 目的

holder コード path で `unwrap` / `expect` / `panic! ` / 配列添え字外 / integer overflow (release で abort) 等が混入した場合、CI で検知する。

## 案

### 案 A — clippy lint 単位で attribute 適用 (最軽量)

holder_child_main と隣接する async-signal-safe 関数群に:

```rust
#[deny(clippy::panic)]
#[deny(clippy::unwrap_used)]
#[deny(clippy::expect_used)]
#[deny(clippy::indexing_slicing)]
```

を関数属性 or 内側モジュール属性で適用。既存の unwrap/expect は fork 前の準備コードにあるので、対象を絞る。

利点: build system 変更ゼロ、CI がすでに `cargo clippy --workspace -- -D warnings` を回す。
欠点: `clippy::indexing_slicing` は不要検知が多い可能性 (holder は固定長配列のみで安全)。

### 案 B — 別 crate に切り出して panic=abort profile を局所適用

`crates/cache-warden-cli-holder` (仮) に holder_child_main を切り出し、`[profile.release] panic = "abort"` を local 適用。

利点: compiler レベルで unwinding を禁止できる。
欠点: workspace 分離コスト、fork 前準備の親側コードとのシグネチャ結合が煩雑、build system 複雑化。

### 案 C — audit test (静的解析)

holder_child_main の call graph を build 時に走査し、panic 経路を洗い出す (例: `#[track_caller]` + マクロで annotation)。

利点: compile 時保証。
欠点: 静的解析ツール依存、実装コスト高。

## 判断

案 A から着手 (最軽量、既存 CI に乗る)。効かない (false-negative が多い / false-positive で敷居高い) なら案 B/C に格上げ。

## 前提

- DR-0029 bundle 2 完了 (holder コードが確定)

## 参照

- Cargo.toml のコメント (holder の unwinding 禁止理由、panic=abort revert 経緯)
- bundle 2 adversarial review 出力 (LOW panic=abort trade-off)

## 優先度

中 (実運用リスクは既存 code review で担保、regression 保護は preventive)
