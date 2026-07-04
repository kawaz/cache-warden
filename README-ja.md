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

Homebrew (macOS、署名・notarize 済みの `.app` を配布):

```bash
brew install --cask kawaz/tap/cache-warden
```

ソースからビルド:

```bash
cargo build --release -p cache-warden-cli
```

## macOS: Full Disk Access (FDA)

`op`（1Password CLI）をアップストリームコマンドとして使う設定（kv エントリの
`source = "op"`、または authsock ソースの `kind = "op"`）の場合、macOS では
Full Disk Access の付与が必要になる。`daemon register` 実行時に未設定であれば
自動的に案内が表示され、System Settings の Full Disk Access 設定画面が開く。
「CacheWarden」を ON にするだけで設定は完了する（この自動案内は `.app` から
実行した場合のみ働く。ソースビルドしたバイナリから `register` した場合は
案内をスキップする旨の警告が表示される）。

FDA なしでも動作するが、daemon の起動やアップグレードのたびに TCC ダイアログ
が表示される。

## ドキュメント

- [DESIGN-ja.md](./docs/DESIGN-ja.md) — 現実装の説明 (ドメイン + アーキテクチャ)
- [STRUCTURE.md](./docs/STRUCTURE.md) — リポジトリ物理構造
- [ROADMAP.md](./docs/ROADMAP.md) — 将来検討項目
- [decisions/INDEX.md](./docs/decisions/INDEX.md) — 設計判断 (DR) 一覧

## ライセンス

MIT License, Yoshiaki Kawazu (@kawaz)
