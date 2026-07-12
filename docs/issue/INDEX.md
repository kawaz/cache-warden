# Issue INDEX

active な issue の一覧。close 済みは archive/ にあり、ここには載せない。

| date | category | status | slug | 概要 |
|---|---|---|---|---|
| 2026-07-10 | design | idea | [remote-approval-web-passkey](./2026-07-10-remote-approval-web-passkey.md) | Tailscale 直達 + WebAuthn passkey によるリモート承認 (kawaz 裁定 2026-07-10 で確定)。daemon が tailnet 内 HTTPS で承認ページ… |
| 2026-06-14 | idea | idea | [ssh-agent-provider-architecture](./2026-06-14-ssh-agent-provider-architecture.md) | 現状の authsock アダプタは **「中継役（relay）」前提**の名残: |
| 2026-06-14 | bug | idea | [touchid-blocks-blocking-pool](./2026-06-14-touchid-blocks-blocking-pool.md) | SIGN_REQUEST 処理は `spawn_blocking` で blocking pool に乗せ、その中で **`store` の `std::sy… |
| 2026-07-09 | design | idea | [linux-graceful-restart-fexecve-verification](./2026-07-09-linux-graceful-restart-fexecve-verification.md) | graceful restart の Linux 対応 (fexecve + 末尾追記署名 L1 / fs-verity L2)。DR-0029 は macOS 先行、L2 は当面着手しない… |
| 2026-07-09 | design | idea | [graceful-restart-phase3-listener-fd-inheritance](./2026-07-09-graceful-restart-phase3-listener-fd-inheritance.md) | DR-0029 Phase 1 の re-bind 方式を SCM_RIGHTS の listener fd 継承にして断ゼロ化する (任意、着手条件あり)。 |
| 2026-07-12 | task | open | [approver-release-hardening](./2026-07-12-approver-release-hardening.md) | draft-DR-0031 Phase 1.5 の opus47 セキュリティレビューで持ち越しになった硬化項目 (standalone 無効化 / main-thread dispatch / 警… |
| 2026-07-12 | task | open | [guard-require-cwd-constraint](./2026-07-12-guard-require-cwd-constraint.md) | draft-DR-0030 guard に `--require-cwd=PATH` constraint を追加 (direnv 的区画化)。kawaz 提案 (2026-07-12): カジュアルな… |
| 2026-07-12 | task | open | [kv-set-guard-positive-ack](./2026-07-12-kv-set-guard-positive-ack.md) | DR-0030 guard の kv set positive ack (guard_applied) — mixed-version silent no-op 対策。Block 2 レビュー HIGH-1 由… |
| 2026-07-12 | design | open | [authsock-sign-dr0030-guard-scope](./2026-07-12-authsock-sign-dr0030-guard-scope.md) | authsock SIGN 経路 (sign_with_resolved_key) は DR-0012 gate のみで DR-0030 guard を評価しない — 適用可否の裁定… |
| 2026-07-10 | design | open | [migrate-to-macos-process-inspect-crate](./2026-07-10-migrate-to-macos-process-inspect-crate.md) | 既存 process inspect 実装の macos-process-inspect crate への移行 (重複解消) |
| 2026-07-06 | bug | open | [daemon-register-help-output-oneshot](./2026-07-06-daemon-register-help-output-oneshot.md) | v0.22.3 daemon 稼働中に v0.23.0 で `daemon register` 実行、末尾に top-level help が出力され旧 daemon… |
| 2026-06-13 | bug | open | [op-discovery-blocks-startup](./2026-06-13-op-discovery-blocks-startup.md) | `[authsock.sockets.*].keys` を持つ config で起動すると、`run()` の |
| 2026-06-22 | design | open | [custom-touchid-dialog](./2026-06-22-custom-touchid-dialog.md) | cache-warden 独自の TouchID 認証 dialog を実装し、**要求元プロセスの透明性**を 1Password 既定の dialog よ… |
| 2026-06-22 | design | wip | [kv-get-peer-identity-guard](./2026-06-22-kv-get-peer-identity-guard.md) | cache-warden の `kv set` 時に **peer-identity constraint** を declarative に付与し、`kv … |
| 2026-06-15 | design | pending-sublimation | [changelog-md-adoption](./2026-06-15-changelog-md-adoption.md) | DR-0024 / DR-0025 のような minor breaking change (= pre-1.0 で minor bump、API surfac… |

<!--
雛形メモ (migrate sub-command 用):

- 列構成は固定 (= 上記 5 列、列名と順序を変えない)
- 行の {{rows}} は migrate が走査後の active issue から生成 (= 全件再生成)
- ソート規約:
  1. status 優先順: idea → open → wip → blocked → pending-sublimation
  2. 同 status 内は date 降順 (= 新しい起票が上)
- 各行: 日付 / category / status / [slug](リンク) / 本文 1 行目から 80 文字以内 の 5 列
- 概要は 80 文字を超えたら末尾を「…」で省略
-->
