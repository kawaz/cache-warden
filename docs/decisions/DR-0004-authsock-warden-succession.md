# DR-0004: authsock-warden の後継・吸収方針

- Status: Active
- Date: 2026-06-10

## Context

DR-0003 で cache-warden のコアを「秘密値のセキュアキャッシュ」と定め、SSH 鍵管理を
その上のプロトコルアダプタと位置づけた。これにより cache-warden は authsock-warden の
**後継コア**となる。authsock-warden が実装済みの機能（鍵管理 / フィルタ / ポリシー /
1Password ローカル署名 / メモリ保護 / サービス登録）を、cache-warden 上の「authsock アダプタ」
として取り込む方針が要る。

方向と原則のみを定める。移植の詳細（コードの具体的な切り分け、API 境界、スケジュール）は
実装フェーズで詰める。決めすぎない。

## Decision

### authsock-warden の機能は「authsock アダプタ」として移植する

authsock-warden は SSH agent proxy + 鍵セキュリティ製品である。その資産を、コア（KV キャッシュ）
に依存する一つのアダプタとして cache-warden へ移植する。authsock-warden 自体は将来引退する。

### 移植対象資産の整理（コア vs アダプタ）

移植にあたり、どの機能が「コア（再利用される基盤）」で、どれが「authsock アダプタ固有」かを
区別する。境界の精密化は実装フェーズに送るが、初期の振り分け方針は以下:

**KV コアに入るもの（秘密値ドメインの基盤、複数アダプタで共有）**

- TTL 管理（soft TTL / hard TTL の二段階ライフサイクル）
- プロセス認証（プロセスツリー遡上による要求元検証）
- 再認証（soft TTL 切れ時の TouchID 等によるキャッシュ延長）
- メモリ保護（mlock / zeroize、anti-debug）

**authsock アダプタに入るもの（SSH 鍵という秘密値の種別固有）**

- SSH agent protocol の実装（proxy / listen）
- 鍵フィルタ（ソケット単位の鍵フィルタリング）とアクセスポリシー
- 1Password ローカル署名
- 鍵ライフサイクル（複数鍵ソース統合 / per-key タイムアウト + 4 状態ライフサイクル）

> プロセス認識アクセス制御は、汎用の「プロセス認証」をコアに置き、その上で「どのソケット /
> どの鍵に誰が触れるか」というポリシー解釈を authsock アダプタ側に置く分割を初期方針とする。
> 厳密な層の切り方は移植時に確定する。

サービス登録（launchd plist / systemd unit 生成）は、デーモンを起動する仕組みなので
コア（サーバ）側の関心になる見込みだが、最終的な所属は実装フェーズで判断する。

### 移行パス（全フェーズで kawaz の日常利用を壊さない）

| Phase | 内容 |
|---|---|
| Phase 0（現状） | authsock-warden が日常稼働。cache-warden は雛形のみ |
| Phase 1（並走） | cache-warden に KV コア + authsock アダプタを実装。authsock-warden と **別ソケット**で並走させ、実利用は authsock-warden のまま |
| Phase 2（パリティ） | authsock アダプタが authsock-warden と機能パリティを達成。並走で挙動を突き合わせる |
| Phase 3（切替） | 利用ソケットを cache-warden 側へ切り替える。authsock-warden はフォールバックとして残置 |
| Phase 4（引退） | 安定を確認後、authsock-warden を引退させる |

各フェーズの不変条件: **kawaz の日常の鍵利用（SSH 署名 / 1Password 連携）を中断させない**。
切替は可逆な形で進め、問題が出たら旧経路へ戻せる状態を保つ。

### 並走期間の二重メンテ最小化

並走期間（Phase 1〜3）に authsock-warden と cache-warden の両方を直し続ける負担を避けるため:

- authsock-warden への新規機能追加は原則止め、バグ修正のみに絞る。
- 移植は「コアを先に固め、アダプタを薄く乗せる」順で進め、ロジックの正本を cache-warden 側へ
  早期に寄せる。
- パリティ検証は手作業の突き合わせではなく、可能な範囲で並走時の挙動比較で行う（詳細は実装フェーズ）。

## Alternatives Considered

- 案 A: authsock-warden を恒久的に併存させ、KV だけ cache-warden に持つ
  - 不採用理由: コア（KV）と SSH アダプタが別プロセス・別リポに分かれ続けると、プロセス認証 /
    メモリ保護 / 再認証といった共有基盤が二重実装になる。DR-0003 で「SSH は KV コア上のアダプタ」
    と位置づけた以上、同一コア上に統合する方が素直。

- 案 B: 一括で authsock-warden を停止し cache-warden へ全面移行する（並走しない）
  - 不採用理由: kawaz の日常利用（鍵署名）を止めるリスクが高い。可逆な並走 → 切替の段階移行で、
    壊れたら戻せる状態を保つ方が安全。

## Consequences

- cache-warden は authsock-warden の後継となり、最終的に authsock-warden は引退する。
- 並走期間中は二つのデーモンが別ソケットで動く前提になる（リソース・設定の二重持ちが一時的に発生）。
- authsock-warden リポへの変更は本リポの管理対象外。移植は cache-warden 側へコードを取り込む形で行い、
  authsock-warden リポは（引退まで）バグ修正中心の保守にとどめる。
- コア / アダプタの層の切り方、サービス登録の所属、パリティ検証の具体手段は実装フェーズへ送る。

## 関連

- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コアドメインの確定とアダプタ構造
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib / cli 分離（不変）
- authsock-warden リポ `docs/decisions/DR-018-kv-cache-warden.md` — セキュア KV キャッシュ構想
- authsock-warden リポ `docs/design.md` — 移植対象となる既存機能の設計
