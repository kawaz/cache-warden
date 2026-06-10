# DR-0002: Workspace 構成

- Status: Active
- Date: 2026-04-10

## 決定

stable-which と同じ workspace 分離パターンを採用。

| Crate | 役割 | 依存 | Publish |
|---|---|---|---|
| `cache-warden` | ライブラリ | 最小（std のみ目標） | crates.io |
| `cache-warden-cli` | CLI バイナリ | cache-warden, serde, serde_json | No（Homebrew 配布） |

## 理由

- ライブラリ利用者に孫依存を強制しない
- stable-which, diesel, sqlx と同じ Rust エコシステムの王道パターン
- CLI は Homebrew / GitHub Releases で配布
