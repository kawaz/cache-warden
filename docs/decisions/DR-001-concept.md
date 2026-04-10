# DR-001: cache-warden コンセプト

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

```
~/.cache-warden/
  sockets/
    ssh-agent -> /var/folders/xx/.../ssh-agent.sock
    gpg-agent -> /run/user/1000/gnupg/S.gpg-agent
  config.toml
```

- `~/.cache-warden/sockets/<name>` が安定パス（symlink）
- 実際のソケットパスは環境に応じて動的に解決
- 設定ファイルでサービスごとのソケットパス解決ルールを定義

## 関連プロジェクト

- **authsock-warden**: SSH/GPG Agent のソケット管理に特化したツール。cache-warden はより汎用的な位置づけ
- **stable-which**: バイナリパスの安定化。cache-warden はソケット/キャッシュパスの安定化

## 未決定事項

- 設定ファイルの形式（TOML? YAML?）
- サービスディスカバリの仕組み
- launchd/systemd との統合方法
- 暗号化ソケットのサポート
