# cache-warden

> [English](./README.md) | 日本語

秘密値を安全に、かつ速くキャッシュする番人。

## 解決する問題

秘密値（API トークン、DB パスワード、SSH 鍵など）は、安全に保ちたい一方で速く使いたい。
op CLI はセキュアだが遅く（item あたり 0.5〜1 秒）、環境変数は速いがメモリから漏れる。
cache-warden は「速くてセキュアで、TTL が切れたら生体認証で延長する」キャッシュを提供する。

## 仕組み

cache-warden のコアは秘密値のセキュアキャッシュ:

1. 秘密値を `static`（直接の値）または `command`（`op read ...` 等の上流コマンド）で登録する
2. soft TTL / hard TTL の二段階でライフサイクルを管理する。soft TTL 切れは TouchID 等の
   再認証で延長、hard TTL 切れは zeroize で破棄する
3. プロセスツリー遡上で要求元を認証し、メモリ保護（mlock / zeroize）で値を守る

SSH 鍵管理（旧 authsock-warden の機能）は、このコアの上に載る一つのプロトコルアダプタとして
取り込まれる（cache-warden は authsock-warden の後継）。

## インストール

```bash
cargo build --release -p cache-warden-cli
```

## ドキュメント

- [DESIGN-ja.md](./docs/DESIGN-ja.md) — 現実装の説明 (ドメイン + アーキテクチャ)
- [STRUCTURE.md](./docs/STRUCTURE.md) — リポジトリ物理構造
- [ROADMAP.md](./docs/ROADMAP.md) — 将来検討項目
- [decisions/INDEX.md](./docs/decisions/INDEX.md) — 設計判断 (DR) 一覧

## ライセンス

MIT License, Yoshiaki Kawazu (@kawaz)
