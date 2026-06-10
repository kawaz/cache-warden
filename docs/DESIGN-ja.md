# cache-warden 設計

> [English](./DESIGN.md) | 日本語

## ドメイン

### 解こうとしている問題

秘密値（API トークン、DB パスワード、SSH 鍵など）の取り扱いには、相反する二つの要求がある:

- **安全に保ちたい**: メモリ上で保護し（mlock / zeroize）、取得元はセキュアな経路
  （1Password / op CLI など）を通したい。
- **速く使いたい**: op CLI は item あたり 0.5〜1 秒かかり、毎回叩くと体感が悪い。一方で
  環境変数に平文で置くと `/proc/PID/environ` などから漏れる。

この緊張を解くのが、**TTL 付きの秘密値キャッシュ + プロセス認証 + 再認証（TouchID 等）** の
組み合わせである。「速くてセキュアで、TTL が切れたら生体認証で延長する」キャッシュを提供する。

SSH 鍵もまた「キャッシュされる秘密値の一種」であり、SSH agent protocol はそのコアの上に乗る
一つのプロトコルアダプタにすぎない、と捉え直せる。cache-warden はこの捉え直しを製品構造に
反映する（背景の構想は authsock-warden リポ `docs/decisions/DR-018-kv-cache-warden.md` を継承。
本リポはその「別プロジェクト化」の実現にあたる。DR-0003）。

### 扱う概念

- **キャッシュエントリ**: 名前付き（KEY）の秘密値。value ソースと TTL、保護状態を持つ。
- **value ソース**: 値の供給元。二種類:
  - `static`: `set` 時に直接与えられた値（パイプ / 引数）。hard TTL 切れ後は再取得不可（再 set が必要）。
  - `command`: 上流コマンド（例 `op read ...`）の実行結果。hard TTL 切れ後はコマンド再実行で再生成できる。
- **soft TTL / hard TTL**: 二段階のライフサイクル。
  - **soft TTL 切れ**: 上流に取りに行かず、ユーザを再認証（TouchID 等）してキャッシュを延長する。
  - **hard TTL 切れ**: メモリから zeroize して破棄する。`command` 型は再取得、`static` 型はエラー。
- **プロセス認証**: 要求元プロセスをプロセスツリー遡上で検証し、誰が値を取れるかを制御する。
- **再認証**: soft TTL 切れ時のユーザ認証手段（TouchID / LocalAuthentication など）。
- **アダプタ**: コアの上に載るプロトコル境界。SSH 鍵を扱う authsock アダプタ、KV を直接扱う
  KV アダプタ（CLI / socket API）など。

### 主なユースケース

```bash
# command ソース: 上流を遅延キャッシュし、soft TTL 切れは再認証で延長
cache-warden kv set DB_PASSWORD --command "op read 'op://vault/item/password'" --soft-ttl 1h --hard-ttl 24h

# static ソース: その場の値をキャッシュ
cache-warden kv set TEMP_CERT --value "$(cat cert.pem)" --soft-ttl 8h

# 取得（キャッシュヒットは数 ms）
cache-warden kv get DB_PASSWORD
```

> 上記の CLI 表記はドメインを説明するためのイメージであり、サブコマンド体系の正式仕様ではない
> （control socket プロトコル設計とセットで確定する。下記 open question 参照）。

## アーキテクチャ

### レイヤ構造（コア KV ↔ アダプタ群）

```
cache-warden コア（セキュア KV キャッシュ）
  ├─ TTL 管理（soft / hard の二段階ライフサイクル）
  ├─ プロセス認証（プロセスツリー遡上）
  ├─ 再認証（TouchID 等）
  └─ メモリ保護（mlock / zeroize / anti-debug）
        ▲
        │ コア上に載る
        │
  プロトコルアダプタ群
  ├─ authsock アダプタ（SSH agent protocol / 鍵フィルタ / ポリシー / 1Password 署名 / 鍵ライフサイクル）
  └─ KV アダプタ（KV CLI、将来 KV socket API）
```

- 秘密値ドメインの基盤（TTL / プロセス認証 / 再認証 / メモリ保護）は**コアに集約**し、複数アダプタで共有する。
- SSH 鍵管理は「SSH 鍵という秘密値の種別」を扱う**アダプタ**として位置づける。
- **ソケットは cache-warden 自身（サーバ側）が作る**。外部プログラムが作ったソケットに後から
  関与するのではなく、cache-warden がエンドポイントを提供する。

### デーモン構成（単一プロセス直担型、DR-0008）

`cache-warden run` は 1 プロセス（tokio ランタイム）であり、全アダプタを同一プロセス内で直接担う。

```
cache-warden run（単一プロセス / tokio ランタイム）
  ├─ コア（secret / clock / source / entry / store / auth / process）を中心に配線
  ├─ listener task: authsock アダプタ（SSH agent socket）
  ├─ listener task: KV アダプタ
  └─ listener task: control socket（管理 CLI ↔ デーモン）
```

- **全アダプタは同一プロセス内の listener task として直担**し、サブプロセスに分割しない。
  決定打は**秘密値の 1 プロセス閉じ込め**で、子プロセス化すると秘密値が IPC を渡り、
  mlock / zeroize / プロセス認証の保護境界がプロセス間に分散して壊れる。in-process なら
  コアのメモリ保護がそのまま全アダプタに効く。
- **管理 CLI ↔ デーモンは control socket（Unix domain socket）経由**。`kv get / set / del` /
  `status` / `refresh` 等の管理系はこのソケットで通信する。KV を他プロセスからプログラマティックに
  叩く経路（KV socket API）も同じプロトコルに統合する。プロトコルの詳細・メッセージ形式は
  次の設計ステップで決める。
- **コアをデーモンの中心に配線する**。コア（実装済み）を run 経路の中心に置き、アダプタはその上に
  薄く乗せる。
- **サービス登録（launchd / systemd）は単一バイナリ + `run` 引数**で行う。
- **同期処理（op CLI 呼び出し等）は `spawn_blocking` で隔離**する。

### Workspace 構成（DR-0002）

| Crate | 役割 | 依存 | Publish |
|---|---|---|---|
| `cache-warden` | ライブラリ（コアロジック） | 最小（std のみ目標） | crates.io |
| `cache-warden-cli` | CLI バイナリ | cache-warden, serde 等 | No（Homebrew 配布） |

設計原則:

- ライブラリは依存最小（`Serialize` 等の serde 依存は CLI 側に寄せる）。ライブラリ利用者に
  孫依存を強制しない。
- stable-which と同じ workspace 分離パターン（Rust エコシステムの王道）。
- CLI は Homebrew / GitHub Releases で配布。

### value ライフサイクル（概念）

```
set ──> [キャッシュ保持] ──soft TTL 切れ──> 再認証(TouchID)
            │                                   │成功→延長して保持
            │                                   │失敗→取得不可
            └──hard TTL 切れ──> zeroize で破棄
                                  │ command 型: コマンド再実行 → 再認証 → 再生成
                                  │ static 型 : エラー（再 set が必要）
```

## open question（未確定・「朧げ」な部分）

正直に列挙する。決めすぎず、実装フェーズで詰める。

- **コア / アダプタの層の精密な切り方**: 特に「プロセス認識アクセス制御」をコア（汎用プロセス認証）と
  アダプタ（ソケット / 鍵ごとのポリシー解釈）にどう分けるか（DR-0004 で初期方針のみ）。
- **サービス登録（launchd / systemd）の所属**: コア（サーバ起動）側かアダプタ側か。
- **TouchID 実装方式**: security-framework / objc2 のどちらを使うか（authsock-warden DR-018 でも未決）。
- **control socket のプロトコル設計**: 管理 CLI ↔ デーモンの通信と KV socket API を統合した
  1 本のプロトコル（メッセージ形式・コマンド体系・プロセス認証との接続）。ホスティングは
  確定済み（DR-0008）で、これが次の主要設計項目。
- **CLI サブコマンド体系の正式仕様**: ホスティングは確定済み（DR-0008）。control socket
  プロトコル設計とセットで確定する。
- **static 型の hard TTL 切れ時のユーザ通知方法**。

## authsock-warden との関係・移行パス

cache-warden は authsock-warden の**後継コア**であり、authsock-warden の機能を「authsock アダプタ」
として移植する。authsock-warden は将来引退する。詳細は
[DR-0004](./decisions/DR-0004-authsock-warden-succession.md)。

移行は段階的・可逆に進め、全フェーズで kawaz の日常の鍵利用を中断させない:

| Phase | 内容 |
|---|---|
| Phase 0（現状） | authsock-warden が日常稼働。cache-warden は雛形のみ |
| Phase 1（並走） | cache-warden に KV コア + authsock アダプタを実装、authsock-warden と別ソケットで並走 |
| Phase 2（パリティ） | authsock アダプタが authsock-warden と機能パリティを達成 |
| Phase 3（切替） | 利用ソケットを cache-warden 側へ切替。authsock-warden はフォールバック残置 |
| Phase 4（引退） | 安定確認後、authsock-warden を引退 |

移植対象資産のコア / アダプタ振り分けは DR-0004 を参照。

## スコープ外

- **外部ソケットのパス安定化 / 安定 symlink 提供**: 外部プログラムが作る volatile なソケット
  （docker.sock / 各種 agent socket 等）のパスを後追いで安定化する用途は扱わない。cache-warden が
  作るのはソケットそのもの（サーバ側）である（旧 DR-0001 の構想は DR-0003 で Supersede）。
- cache-warden コアが直接担わないプロトコル変換は、各アダプタの責務。

## 将来検討

- **control socket / KV socket API**: 管理 CLI ↔ デーモンの通信と、他プロセスからプログラマティックに
  KV を操作する経路を 1 本の Unix domain socket プロトコルに統合する（DR-0008、設計は次ステップ）。
- **自前 TouchID**: 上流（op）に頼らず cache-warden 自身が LocalAuthentication で再認証を発行する。
  SSH 鍵署名のゲートにも転用できる。
- **アダプタの追加**: SSH / KV 以外の秘密値プロトコルを扱うアダプタ。

詳細は [ROADMAP.md](./ROADMAP.md) を参照。

## 関連ドキュメント

- [decisions/INDEX.md](./decisions/INDEX.md) — DR 一覧
- [DR-0002-workspace-structure](./decisions/DR-0002-workspace-structure.md) — Workspace 構成
- [DR-0003-secure-kv-core-and-adapters](./decisions/DR-0003-secure-kv-core-and-adapters.md) — コアドメインとアダプタ構造
- [DR-0004-authsock-warden-succession](./decisions/DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針
- [DR-0008-single-daemon-hosting](./decisions/DR-0008-single-daemon-hosting.md) — 単一デーモンプロセス直担型のホスティング形態
- [STRUCTURE.md](./STRUCTURE.md) — 物理構造
- [ROADMAP.md](./ROADMAP.md) — 将来検討
