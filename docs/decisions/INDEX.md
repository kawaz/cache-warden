# Decision Records 一覧

## Active

- [DR-0002](./DR-0002-workspace-structure.md) — Workspace 構成: lib（依存最小・crates.io）/ cli（Homebrew 配布）の分離（stable-which パターン）
- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — コアドメインを「秘密値のセキュア KV キャッシュ」と定める（TTL / プロセス認証 / 再認証 / メモリ保護）。SSH 鍵管理はその上のプロトコルアダプタ。authsock-warden DR-018 構想の別プロジェクト化。命名 `cache-warden` 維持。DR-0001 全体を Supersede
- [DR-0004](./DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針。warden 機能を「authsock アダプタ」として移植 / 移植対象資産の整理（コア vs アダプタ）/ 並走 → パリティ → 切替 → 引退の移行パス
- [DR-0005](./DR-0005-core-security-dependencies.md) — コアの秘密値ゼロ化に `zeroize` crate を例外採用（DR-0002 の依存最小原則に対する意図的例外）。自作 volatile write 案・secrecy 案の却下理由つき
- [DR-0006](./DR-0006-process-inspection-dependencies.md) — プロセス検査（pid → path / ppid / 開始時刻）に `libc` を最小依存として採用（DR-0002 への 2 つ目の意図的例外）。sysinfo 案・raw syscall 案・依存ゼロ案の却下理由つき。authsock-warden の libc 直叩き前例を踏襲
- [DR-0007](./DR-0007-mlock-memory-pinning.md) — 秘密値ページを `mlock` で常時ピン留めしスワップ漏洩を抑止。失敗は fail-open（`is_locked()` で検知可能）/ munlock→zeroize 順 / 不変バッファ設計で Vec 再確保問題を構造的に回避 / feature gate にせず常時有効。追加依存なし（libc は DR-0006 で導入済み）。DR-0005 が「別 DR で判断」とした mlock 採用の決定
- [DR-0008](./DR-0008-single-daemon-hosting.md) — 単一デーモンプロセス直担型。`cache-warden run` = 1 プロセス（tokio）で全アダプタを listener task として in-process 直担（決定打は秘密値の 1 プロセス閉じ込め）。管理 CLI ↔ デーモンは control socket（KV socket API と統合、プロトコル詳細は次ステップ）。サービス登録は単一バイナリ + `run`。内部サブコマンド方式・アダプタ別デーモンを却下。DR-0003 / DR-0004 が残したホスティング形態・デーモン境界を確定
- [DR-0009](./DR-0009-control-socket-protocol-v1.md) — control socket プロトコル v1。transport = UDS（0600 / stale 検知 / 二重起動拒否）、framing = JSON Lines、秘密値は base64（`*_b64`）。コマンド = `ping` / `status`（値非露出）/ `kv.set` / `kv.get` / `kv.del` / `kv.list`。peer 認証 = LOCAL_PEERPID / SO_PEERCRED → ancestry を requester として渡す（解釈はまだしない）。Authenticator は AllowAll 暫定配線。length-prefixed バイナリ・gRPC/CBOR・素 JSON 文字列を却下。DR-0008 が残したプロトコル設計を確定
- [DR-0010](./DR-0010-config-and-reauth-command.md) — TOML config と再認証コマンド方式。実 Authenticator = `CommandAuthenticator`（lib、exit 0=承認/非ゼロ=拒否/spawn失敗=Unavailable、AuthContext を env で渡し秘密値は渡さない、timeout なし、warden DR-009 踏襲）。TOML config（CLI、`deny_unknown_fields`、`$CACHE_WARDEN_CONFIG`→`$XDG_CONFIG_HOME`→`~/.config` 探索、`[daemon].socket`/`[auth].command`/`[kv.*]` 起動時プリロード）。**static を config に書けない設計**（平文秘密値の流出防止、書いたら設定エラー）、auth 省略時=AllowAll、socket 優先順位 CLI>config>default、`config show|path|edit` 追加。ビルトイン TouchID 先行・config への static 値許可・config 必須化を却下。DR-0009 の AllowAll 暫定配線を置換

## Archived

<!-- なし -->

## Moved to research/

<!-- なし -->

## Superseded

- [DR-0001](./DR-0001-concept.md) — cache-warden コンセプト（外部 volatile ソケットパスの安定 symlink 提供）。**Superseded by DR-0003**（コアが「セキュア KV キャッシュ」へ転換、symlink 路線は廃止）。本文は歴史記録として保持
