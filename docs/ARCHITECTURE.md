# Architecture

cache-warden はキャッシュソケットパスの管理・保護ツール/ライブラリ。

## Workspace 構成

| Crate | 役割 | 依存 | Publish |
|---|---|---|---|
| `cache-warden` | ライブラリ | 最小 | crates.io |
| `cache-warden-cli` | CLI バイナリ | cache-warden, serde, serde_json | No（Homebrew 配布） |

## 設計原則

- ライブラリは依存最小（Serialize 等は CLI 側）
- stable-which と同じ workspace 分離パターン

## 関連ドキュメント

- [Design Records](decisions/) — 設計判断とその理由
