# DR-0001: cache-warden コンセプト

- Status: Superseded by DR-0003
- Date: 2026-04-10

> **Superseded by DR-0003**: 本 DR は cache-warden を「外部プログラムが作る volatile な
> ソケットパスへの安定 symlink を提供するツール」として構想していたが、2026-06-10 の kawaz
> レビューでこの前提が否定された。cache-warden のコアは「秘密値のセキュアキャッシュ」へと
> 転換し、SSH 鍵管理はその上のプロトコルアダプタと位置づけ直された（DR-0003）。本文は歴史記録
> として保持する。

## 背景

macOS/Linux でデーモンやサービスが使う Unix ドメインソケットやキャッシュファイルのパスは、OS の一時ディレクトリ（`/tmp`, `$TMPDIR`, `$XDG_RUNTIME_DIR`）に配置されることが多い。これらのパスは以下の理由で不安定:

- macOS の `$TMPDIR` はユーザーごと・ブートごとに変わる（`/var/folders/xx/.../T/`）
- `/tmp` はリブートで消える（tmpfs）
- `$XDG_RUNTIME_DIR` はログアウトで消える場合がある
- パーミッション設定が適切でないとセキュリティリスクになる

具体例:
- SSH Agent のソケット (`SSH_AUTH_SOCK`)
- GPG Agent のソケット
- 1Password CLI のソケット
- Docker のソケット (`/var/run/docker.sock`)

## 問題

1. **パスの不安定性**: ソケットパスが変わると、クライアントが接続先を見失う
2. **パーミッション**: 他ユーザーからアクセス可能な場所に置かれるリスク
3. **再起動時の復旧**: サービス再起動後にソケットが再作成されない、古いソケットファイルが残る
4. **複数サービス間の連携**: サービス A のソケットパスをサービス B が知る方法が統一されていない

## 決定

cache-warden は以下を提供するツール/ライブラリとして設計する:

### コア機能

1. **ソケットパス管理**: 安定したソケットパスを提供し、実際のソケットへの symlink で追従
2. **パス解決**: `cache-warden resolve <service>` でサービスのソケットパスを取得
3. **ヘルスチェック**: ソケットが生きているか監視
4. **クリーンアップ**: 古いソケットファイルの自動削除

### アーキテクチャ

- **ライブラリ crate** (`cache-warden`): コアロジック、依存最小
- **CLI crate** (`cache-warden-cli`): コマンドラインインターフェース、publish = false
- workspace 構成（stable-which と同じパターン）

### 安定パスの設計

> **注記**: この「安定パスの設計」を含む symlink 路線全体が DR-0003 で Superseded された
> （下記本文は当時の歴史記録）。

```
~/.cache-warden/
  sockets/
    ssh-agent -> /var/folders/xx/.../ssh-agent.sock
    gpg-agent -> /run/user/1000/gnupg/S.gpg-agent
  config.toml
```

- 安定パス（symlink）を提供する方針自体は維持
- 実際のソケットパスは環境に応じて動的に解決
- 設定ファイルでサービスごとのソケットパス解決ルールを定義

## 関連プロジェクト

- **authsock-warden**: SSH Agent protocol の proxy と鍵のセキュリティに特化したツール。後継・吸収方針は DR-0004 を参照
- **stable-which**: バイナリパスの安定化（当初コンセプトでの比較対象）

## その後の確定状況

本 DR の symlink 路線は DR-0003 で全面 Superseded された。当初ここに並べていた未決事項
（設定ファイル形式・サービスディスカバリ・launchd/systemd 統合・暗号化ソケット対応）は、
コンセプトが「セキュア KV キャッシュコア + プロトコルアダプタ」へ転換したことで前提ごと
組み替わっている。現行の方針は DR-0003 / DR-0004 と DESIGN を参照。
