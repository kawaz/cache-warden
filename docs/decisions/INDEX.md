# Decision Records 一覧

## Active

- [DR-0002](./DR-0002-workspace-structure.md) — Workspace 構成: lib（依存最小・crates.io）/ cli（Homebrew 配布）の分離（stable-which パターン）
- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — コアドメインを「秘密値のセキュア KV キャッシュ」と定める（TTL / プロセス認証 / 再認証 / メモリ保護）。SSH 鍵管理はその上のプロトコルアダプタ。authsock-warden DR-018 構想の別プロジェクト化。命名 `cache-warden` 維持。DR-0001 全体を Supersede
- [DR-0004](./DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針。warden 機能を「authsock アダプタ」として移植 / 移植対象資産の整理（コア vs アダプタ）/ 並走 → パリティ → 切替 → 引退の移行パス

## Archived

<!-- なし -->

## Moved to research/

<!-- なし -->

## Superseded

- [DR-0001](./DR-0001-concept.md) — cache-warden コンセプト（外部 volatile ソケットパスの安定 symlink 提供）。**Superseded by DR-0003**（コアが「セキュア KV キャッシュ」へ転換、symlink 路線は廃止）。本文は歴史記録として保持
