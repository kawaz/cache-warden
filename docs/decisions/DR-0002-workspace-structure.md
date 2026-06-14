# DR-0002: Workspace 構成

- Status: Active
- Date: 2026-04-10

## 決定

stable-which と同じ workspace 分離パターンを採用。

| Crate | 役割 | 依存 | Publish |
|---|---|---|---|
| `cache-warden` | ライブラリ | 最小（std のみ目標） | crates.io |
| `cache-warden-authsock` | SSH agent protocol アダプタ lib | cache-warden, ssh-key, tokio, bytes, serde/serde_json, 暗号クレート群（ed25519-dalek/rsa/p256/p384/p521 等） | No（アダプタの重い依存隔離のため別 crate 化。DR-0004 参照） |
| `cache-warden-cli` | CLI バイナリ | cache-warden + cache-warden-authsock + serde/tokio/base64/toml/libc/hmac/sha1/sha2/stable-which | No（Homebrew 配布） |

## 理由

- ライブラリ利用者に孫依存を強制しない
- stable-which, diesel, sqlx と同じ Rust エコシステムの王道パターン
- CLI は Homebrew / GitHub Releases で配布
