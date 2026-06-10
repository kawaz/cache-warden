# DR-0008: 単一デーモンプロセス直担型のホスティング形態

- Status: Active
- Date: 2026-06-10

## Context

DR-0003 で cache-warden のコアを「秘密値のセキュア KV キャッシュ」と定め、SSH 鍵管理を
その上のプロトコルアダプタと位置づけた。しかし「アダプタを物理的にどのプロセスが担うか」
（ホスティング形態）と「何をどのプロセスが listen し、どこでソケットを作るか」
（デーモン / サーバプロセスの境界）は DR-0003 / DR-0004 では未確定のまま、DESIGN の
open question として残されていた。

このプロセス構成を確定するため、後継元である authsock-warden の実機構成を裏付け調査した
（確定事実として扱う）:

- authsock-warden は **単一プロセス + 単一 tokio ランタイム（multi-thread）** で動作し、
  ソケットごとに listener task、接続ごとに動的 task を生やす。シャットダウンは watch channel
  で一斉配布する。
- authsock-warden の管理系サブコマンド（keys / refresh / status）は未実装のプレースホルダで、
  CLI ↔ デーモン間 IPC は存在しない。すなわち管理 IPC は cache-warden の新規設計領域である。
- authsock-warden のサービス登録は launchd plist / systemd unit が単一バイナリを
  `run --config <path>` で起動する形。
- authsock-warden では KeyRegistry 等の「コア層」が実装済みなのに run 経路へ未配線で、
  WardProxy がプロトコルと鍵管理を兼任していた（コアが中心に配線されていない）。

## Decision

### 単一デーモンプロセス直担型

`cache-warden run` を 1 プロセス（tokio）とし、全アダプタ（authsock アダプタの SSH agent
socket、KV アダプタ）を **同一プロセス内の listener task として直接担う**。アダプタを
サブプロセスに分割しない。

決定打は **秘密値の 1 プロセス閉じ込め**である。アダプタを子プロセス化すると秘密値が IPC を
渡ることになり、mlock / zeroize / プロセス認証の保護境界がプロセス間に分散して壊れる。
in-process であれば `SecretBytes` の保護がそのまま全アダプタに効く。

### 管理 CLI ↔ デーモンは control socket

`kv get / set / del` / `status` / `refresh` 等の管理系は Unix domain socket（control socket）
経由でデーモンと通信する。authsock-warden DR-018 が将来構想としていた「KV Unix socket API」と
この管理 IPC を **1 本のプロトコルに統合する**。プロトコルの詳細（メッセージ形式・コマンド
体系）は次の設計ステップで決め、本 DR では決めない。

### コアをデーモンの中心に配線する

authsock-warden で起きた「コア層は実装済みなのに run 経路へ未配線（プロキシがコアを兼任）」の
轍を踏まない。実装済みのコア（secret / clock / source / entry / store / auth / process）を
最初からデーモンの中心に配線し、アダプタはその上の listener task として薄く乗せる。

### サービス登録・同期処理

- サービス登録（launchd / systemd）は単一バイナリ + `run` 引数で行う（authsock-warden 踏襲）。
- 同期処理（op CLI 呼び出し等）は `spawn_blocking` で隔離する（authsock-warden の実績踏襲）。

## Alternatives Considered

- 案 A: 内部サブコマンド方式（アダプタをコアが子プロセスとして spawn する）
  - 不採用理由: 秘密値が IPC を渡ることになり、メモリ保護境界がプロセス間に分散・露出する。
    プロセス管理も複雑化する。

- 案 B: アダプタ別デーモン（アダプタごとにプロセスを分離する）
  - 不採用理由: 案 A と同じ秘密値の境界分散に加え、サービス登録が複数 unit に分かれて運用が
    複雑化する。プロセス分離による隔離の利益は、アダプタ間で秘密値の保護基盤を共有する必要性の
    前では成立しない。

## Consequences

- ホスティング形態とデーモン境界が「単一プロセス直担」に確定する。DESIGN の open question 1
  （ホスティング形態）と 2（デーモン境界）はこれで解消する。
- **次の主要設計項目は control socket プロトコルの設計**になる。管理 IPC と KV socket API を
  1 本に統合するため、メッセージ形式・コマンド体系・認証（プロセス認証との接続）をまとめて
  設計する必要がある。CLI サブコマンド体系の正式仕様もこのプロトコル設計とセットで確定する。
- アダプタは in-process な listener task として実装するため、秘密値は `SecretBytes` のまま
  プロセス内に留まり、mlock / zeroize / プロセス認証が全アダプタへ一様に効く。
- コアを run 経路の中心に最初から配線するため、authsock-warden の「コア未配線」状態は移植時に
  解消される（移植方針は DR-0004）。

## 関連

- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コアドメインの確定とアダプタ構造（本 DR が未確定として残したホスティング形態を確定）
- [DR-0004-authsock-warden-succession](./DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針（サービス登録の所属・移植の順序）
- [DR-0007-mlock-memory-pinning](./DR-0007-mlock-memory-pinning.md) — mlock によるメモリ保護（1 プロセス閉じ込めが保護を全アダプタへ効かせる前提）
- authsock-warden リポ `docs/decisions/DR-018-kv-cache-warden.md` — KV Unix socket API 構想（本 DR で管理 IPC と統合）
