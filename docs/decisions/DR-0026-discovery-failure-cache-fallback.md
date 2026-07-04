# DR-0026: op discovery 失敗時の disk-cache fallback

- Status: Accepted
- Date: 2026-07-04
- Related: DR-0023 (起動時 op discovery ブロッキング解消。本 DR はその Phase 2 前段の hotfix) / DR-0022 (fetch 失敗 backoff。stale 鍵の sign 失敗は同経路に畳まれる) / issue 2026-06-13-op-discovery-blocks-startup (対象症状)

## Context

launchd 経由起動の daemon では op CLI の biometric 認可路が UI session に届かず、
`op item list` が永久 hang → wall-clock 30s timeout で discovery 失敗になる
(issue 2026-06-13 の 2026-06-22 追観測で再現確認済み)。このとき
`discover_keys` は Err を返し、呼出側が空 Vec に畳むため **0 鍵で serving =
SSH signing 全停止** が dogfood の致命症状として残っていた (P2)。

一方、disk cache (`op_map.json`) には前回成功時の public key 一式が残っている。
public key の列挙に op は本来不要で、秘密鍵は sign 時に lazy fetch する構造
(DR-0023 / A-3a) が既にあるため、「列挙だけ cache で継続する」余地があった。

## Decision

`discover_keys` の戻り値を `DiscoveryOutcome` enum に変更する:

- `Fresh { keys, cache }` — `op item list` 成功。従来通り。呼出側は cache を保存
- `Stale { keys, error }` — `op item list` 失敗。disk cache から復元した鍵を返す。
  **`Stale` は cache フィールドを持たない** = 呼出側がこの経路で cache を
  再保存することを型レベルで不可能にする (一時的な op 障害で known-good な
  mapping を破壊しない)

fallback の境界規則 (source 境界を跨いだ鍵の混入防止):

1. **provenance 必須**: `CachedKey` に `CacheProvenance { account }` を追加。
   fresh discovery 時に「その鍵を発見した `op --account`」を刻む。fallback は
   provenance の account が discovery 時の account と一致するエントリだけを対象
   にする。識別子には config のソースラベル名ではなく **ドメイン識別
   (op アカウント)** を使う (ラベルはユーザが自由に rename でき境界として不安定)
2. **legacy エントリは不適格**: 旧スキーマ (provenance 無し) のエントリは
   `#[serde(default)]` で `None` として読める (ファイル互換維持) が、出自を証明
   できないため fallback には**使わない** (保守側)。成功 discovery の warm-cache
   hint (fingerprint fast path) としては従来通り有効
3. **`account: None` は「既知の default アカウント」**: `Some(CacheProvenance {
   account: None })` (= op CLI default アカウントで発見) と `provenance: None`
   (= 出自不明) は区別され、前者のみ default アカウントの source に対して適格
4. **vault / item filter をミラー**: source の `op://VAULT` / item 指定に
   合致するエントリのみ。live の `op item list` が列挙した範囲を fallback が
   広げることはない
5. 空 public key のエントリは除外 (列挙数と signing 能力を一致させる)、
   fingerprint で dedup (live と同じ規則)

呼出側 (`discover_all_sources`) は Stale 時に
`serving N key(s) from stale cache` を stderr へ可視化する。

## Security

- public key は秘匿情報ではない。sign は従来通り op fetch + TouchID を強制する
  ため、stale な public key を列挙しても **confidentiality は不変、availability
  のみ改善** (get/set 禁止と del/forget 許可が別軸であるのと同じ整理)
- 1Password 側で削除済みの鍵が cache に残って列挙され続けるリスク: sign 時の
  op fetch が失敗し DR-0022 backoff に畳まれる。次回の成功 discovery で cache
  が上書きされ列挙からも消える

## Rejected

- **全 cache 無条件 fallback**: 複数 account / vault 構成で source 境界を跨いで
  鍵が混入する。provenance 境界が必須
- **config ソースラベルを provenance に使う**: rename で境界が崩れる。ドメイン
  識別 (account) を採用
- **legacy エントリも fallback に含める**: 出自を証明できないエントリを境界
  判定に通すのは本 DR の目的 (境界の保証) と矛盾
- **Stale 時の cache 再保存**: 一時障害で known-good mapping を失う。enum の
  構造 (Stale に cache を持たせない) で物理的に防止

## Consequences

- P2 (0-key serving) は解消: launchd で op が hang しても前回鍵で signing 継続
  (初回 sign 時に op fetch が必要な点は不変)
- P1 (listener 起動が discovery 完了まで最大 30s 遅延) と P3 (launchd context
  の biometric 到達不能) は**残存**。DR-0023 Phase 2 (listener 先行 bind +
  background discovery) で扱う。本 DR の cache→`DiscoveredKey` 変換は Phase 2
  の registry seed にそのまま再利用できる
