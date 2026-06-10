# DR-0003: セキュア KV キャッシュコア + プロトコルアダプタ

- Status: Active
- Date: 2026-06-10
- Supersedes: DR-0001（コンセプト全体）

## Context

cache-warden のコアドメインを「秘密値のセキュアなキャッシュ（secure KV）」と定める。

秘密値（API トークン、DB パスワード、SSH 鍵など）を扱うとき、二つの相反する要求がある:

- **安全に保ちたい**: メモリ上で保護し（mlock / zeroize）、取得元（1Password 等）は
  遅くてもセキュアな経路を通したい。
- **速く使いたい**: op CLI は item あたり 0.5〜1 秒かかる。毎回叩くと体感が悪い。
  かといって環境変数に置くと `/proc/PID/environ` 等から漏れる。

この緊張を解くのが「TTL 付きの秘密値キャッシュ + プロセス認証 + 再認証（TouchID 等）」
という組み合わせである。SSH 鍵もまた「キャッシュされる秘密値の一種」であり、
SSH agent protocol はそのコアの上に乗る一つのプロトコルアダプタにすぎない、と捉え直せる。

この構想は authsock-warden の `DR-018`（Status: Proposed）で「セキュア KV キャッシュ」
として提案されたものである。DR-018 は二つの実現方向を併記していた:

- 第一候補: authsock-warden に `warden kv` サブコマンドとして統合する。
- 残された可能性: 別プロジェクト（cache-warden）として独立させる。

本 DR は **後者を選び、cache-warden をそのコアの実装場所とする**。

## Decision

### cache-warden = セキュア KV キャッシュコア + プロトコルアダプタ

cache-warden のコアドメインは「秘密値の安全なキャッシュ」とする。提供する核は:

- **TTL 管理**: soft TTL / hard TTL の二段階。
- **プロセス認証**: 要求元プロセスをプロセスツリー遡上で検証し、誰が値を取れるか制御する。
- **再認証**: soft TTL 切れ時に TouchID 等でユーザを認証し、上流に取りに行かずキャッシュを延長する。
- **メモリ保護**: mlock / zeroize による秘密値のメモリ上保護。

この核の上に **プロトコルアダプタ**を載せる。SSH 鍵管理（SSH agent protocol）は
「秘密値の一種を扱うアダプタ」として位置づけ、KV はもう一つのアダプタ（KV CLI / KV socket API）
として位置づける。ソケットを作るのは cache-warden 自身（サーバ側）であり、外部が作った
ソケットへ後から関与する設計ではない。

### DR-018 構想の「別プロジェクト化」を選ぶ

DR-018 の第一候補（authsock-warden への統合）ではなく、別プロジェクト（cache-warden）
として独立させる。この選択を裏づける authsock-warden 側の確定事実（前回調査）:

- authsock-warden の SSH agent proxy / 鍵セキュリティ機能は実装済み（複数鍵ソース統合 /
  ソケット単位の鍵フィルタ / プロセス認識アクセス制御 / per-key タイムアウト + 4 状態
  ライフサイクル / 1Password ローカル署名 / mlock・zeroize・anti-debug / launchd・systemd
  サービス登録）。
- 一方 DR-018 が構想する soft/hard TTL・再認証・`warden kv` サブコマンドは **未実装**。
  signer / warden_proxy は「DR-018 の adapter 層側」だけが先行整備された状態にとどまる。

### 命名: 現名 `cache-warden` を維持する（2026-06-10 kawaz レビューで確定）

コアドメインが「セキュア KV キャッシュ」になったことで、`cache-warden` という名前は
このドメインにそのまま自然に対応する（「キャッシュを番人として守る」）。改名は不要。

## Alternatives Considered

- 案 A: `warden kv` として authsock-warden へ統合する（DR-018 の第一候補）
  - 不採用理由: 責務の核が「SSH」ではなく「セキュアキャッシュ」へと移った以上、authsock の
    名を冠した製品の内側にコアを置く構造は据わりが悪い。コアの名を冠した新プロジェクトに
    SSH 機能をアダプタとしてぶら下げる方が、ドメインと製品名の対応が素直になる。共有コードの
    重複懸念（DR-018 が統合を推した主因）は、authsock-warden の機能を本リポへ移植して
    一本化することで解消する（DR-0004 の後継・吸収方針）。デーモン一本化も移植後は本リポ側で実現する。

- 案 B: 旧 symlink 構想（旧 DR-0001）を維持する
  - 不採用理由: 旧 DR-0001 は「外部プログラムが作る volatile ソケットへの安定 symlink を
    提供する（docker.sock / 各種 agent socket のパス安定化）」という構想だったが、kawaz
    レビューで前提が否定された。cache-warden が作るべきはソケットそのもの（サーバ側）であり、
    外部ソケットのパスを後追いで安定化する path 層という位置づけは取らない。外部ソケットの
    symlink 安定化はスコープ外とする（DESIGN「スコープ外」節）。

## Consequences

- cache-warden のコアドメインが「秘密値のセキュアキャッシュ」に確定する。これが以降の全 DR の前提になる。
- authsock-warden の機能は本リポへ「authsock アダプタ」として移植され、authsock-warden は
  将来引退する（移植・移行の方針は DR-0004）。
- ソケットは cache-warden 自身が作る。ただしアダプタのホスティング形態（内部サブコマンド方式か、
  本体サーバプロセスが直接担うか）は未確定であり、DESIGN の open question として明示する。
- authsock-warden 側 DR-018 のテキストは authsock-warden リポの管理対象なので、本リポからは
  変更しない。別プロジェクト化を選んだという整理結果は本 DR を正とする。
- 命名は `cache-warden` 維持で確定（2026-06-10 kawaz レビュー）。

## 関連

- [DR-0001-concept](./DR-0001-concept.md) — 当初構想（symlink 路線、本 DR で Superseded）
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — Workspace 構成（不変）
- [DR-0004-authsock-warden-succession](./DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針
- authsock-warden リポ `docs/decisions/DR-018-kv-cache-warden.md` — セキュア KV キャッシュ構想（本 DR が別プロジェクト化を選んだ元構想）
