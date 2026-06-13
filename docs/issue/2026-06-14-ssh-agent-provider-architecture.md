# ssh-agent Provider 再設計（アイデア記録）

- status: idea
- 記録: 2026-06-14（kawaz との議論メモ。命名は暫定、未決）
- 関連: DR-0004（authsock 後継）/ DR-0018（型付き source・authsock NS）を拡張ないし supersede する候補。DR-0014（kv definition）/ DR-0017（namespace）の思想と一貫。
- 関連 issue: [2026-06-13-op-discovery-blocks-startup](./2026-06-13-op-discovery-blocks-startup.md)（この再設計の pubkey 列挙/秘密 lazy 分離で解消できる）

## 動機

現状の authsock アダプタは **「中継役（relay）」前提**の名残:
- 鍵の **discovery（list 提供）が `SSH_AUTH_SOCK` upstream ありき**。
- 鍵 **取得は source 経由**（op:// 等）、source 対応が無ければ **署名 proxy にフォールバック**。
- dispatch は `RequestIdentities` / `SignRequest` のみ実処理、他（Add/Remove/Lock/Unlock）は `failure()`（= read-only）。

これは authsock-warden が「proxy の立場でうまくやる」コンセプトだった名残。**cache-warden は kv を持つので、upstream 無しでも ssh-agent の 1 次プロバイダになれる**。よって discovery を upstream ありきから外せる。

本命は **「list 取得の upstream ありき」を外すこと**。ssh-add 対応はモデル上の write 口として在るが**優先度は低い**（やらない人は自然に縮退できる設計にする）。

## 概念階層とデータフロー

```
  ssh client (git, ssh, ...)
        │  ssh-agent protocol
        ▼
  ┌─────────────────────────────────────────────┐
  │ Endpoint（= unix socket、現 [authsock.sockets.*]）│  ← 公開層
  │   - selector で Provider の鍵を filter 公開       │
  │   - access-policy (DR-0012) を適用              │
  └───────────────┬─────────────────────────────┘
                  │ list_identities() / sign()
                  ▼
  ┌─────────────────────────────────────────────┐
  │ Provider（共通 interface、合成可）              │  ← 抽象層（新）
  │   trait: list_identities()->[Identity], sign() │
  │                                               │
  │   ├ Composite（子 Provider の union + routing）  │
  │   ├ KeySource     … core kv の source から提供   │
  │   ├ UpstreamAgent … 外部 agent を proxy          │
  │   └ Keyring       … 実体保持（ssh-add 投入先）    │
  └───────┬───────────────┬───────────────┬───────┘
          ▼               ▼               ▼
   core kv (Store)   外部 SSH_AUTH_SOCK   in-memory 鍵
   + source 解決      (別 agent)          (mlock'd)
   (op:// / static)
```

- **core kv（既存）**: 秘密値を TTL/mlock/source/policy 付きで保持。**ssh 秘密鍵も「値」の一種**。鍵の値は `source`（op:// / static / command）から (再)生成（DR-0014/0018）。
- **Provider（新・抽象層）**: 「どの鍵があるか＋どう署名するか」に答える統一 interface。**upstream を「外部 agent socket のパス文字列」から「Provider」へ一般化**したもの。外部 agent も自己定義 source list も同じ interface に化ける。
- **Endpoint = socket（既存を一般化）**: Provider（合成済み）の鍵を selector で filter し、access-policy を付けて unix socket として公開。

## 状態の所在（storage）— 秘密は core kv、公開鍵は adapter index

**重要な構造原則**: Provider（特に Keyring）は**自前の秘密ストアを持たない**。秘密鍵の保存先は core kv に一本化する（並行ストアを作ると mlock/zeroize/TTL/policy が二重管理になり破綻、design-thinking のワークアラウンドフィールド禁止）。

| データ | 所在 | 理由 |
|---|---|---|
| **秘密鍵（秘密）** | **core kv**（`source` = `static`(ssh-add 投入) / `op://`(宣言)） | mlock/zeroize/TTL/再認証/policy を 1 箇所に集約 |
| **公開鍵 + メタ（非秘密）** | **adapter 側 index** | `REQUEST_IDENTITIES` は公開鍵のみ返す。列挙のたびに秘密を fetch（op / TTL/policy ゲート）したくない。非秘密なので軽く常駐・cache・**永続化も可** |

- **list（列挙）**: adapter index の公開鍵だけで即答 → **秘密に触れない**。
- **sign**: その時だけ core kv から秘密鍵を取得（TTL/policy/再認証ゲート適用）。
- → 「pubkey 列挙 と 秘密 lazy fetch の分離」。**op-discovery-blocks-startup の解**であり、DR-0018 force_eager（pubkey 常駐）を「公開鍵 index は常駐/永続、秘密は lazy」に精緻化したもの。

**含意（Provider 分割への影響）**:
- KeySource / Keyring は**どちらも core kv backed**（秘密は kv、公開鍵は adapter index）。違いは entry の **source 種別**（`op://` pull か `static` push か）・**write 可否**（Keyring は ADD で static kv entry を作る）・**lifecycle**（宣言/永続定義 か runtime/ephemeral か）。
  - → 突き詰めると「**1 つの kv-backed Provider**、entry の source とwritability で振る舞いが分かれるだけ」に畳める可能性もある。KeySource と Keyring を別 Provider として立てるか、1 つにするかは設計判断（lifecycle の明確さ vs 構造の単純さ）。
- **UpstreamAgent だけは local storage を持たない**（純 proxy）。list は upstream へ転送して公開鍵取得（or cache）、sign も転送。core kv 非関与。
- 「Keyring」という名は**外部から見た振る舞い**（鍵を add/list できる holder）を指す。実際の秘密保存は core kv に委譲する点に注意（名前が store を含意するが物理ストアではない）。

## 3 つの Provider（命名は暫定 / kawaz feedback 反映）

> 命名のもやもや点を反映した叩き台。確定ではない。

| 役割 | 暫定名 | 旧呼称 | 内容 | 備考 |
|---|---|---|---|---|
| source 由来 | **KeySource**(Provider) | KvSource | core kv に宣言した source（op:// 等）から鍵を提供。1 次プロバイダ | 「KvSource」は core の kv と被るので回避（鍵自体が値＝Key が source 対象）。代替: SourcedKeys / DeclaredKeys |
| 外部 agent proxy | **UpstreamAgent**(Provider) | Forwarding | 外部 `SSH_AUTH_SOCK`（別 agent）へ list/sign を**転送（proxy/relay）**。既存 1Password app agent / yubikey 等を再宣言せず取り込む用途 | 「Forwarding」が何を forward するか不明瞭 → 「外部 agent を upstream として持つ Provider」と明示。代替: AgentProxy |
| 実体保持 | **Keyring**(Provider) | LocalAdded | agent が直接保持する書き込み可能な鍵置き場。ssh-add の投入先 | 「LocalAdded」は ssh-add に引きずられすぎ。security/ssh ドメインで「メモリ上に保持する鍵の集合」の idiomatic 語が Keyring（keychain/gnome-keyring 系譜）、core の `Store`(kv) とも非衝突。次点 Registry（register 意味は合うが台帳寄り）、Repository は VCS 連想で不採用 |
| 合成 | **Composite**(Provider) | — | 子 Provider 群の union（dedup）+ sign routing。複数 upstream をソースにする = この一形態 | |

**write の局所性**: ADD/REMOVE は Keyring のみに作用。KeySource / UpstreamAgent は read（後者は read-through proxy）。

## 主要ユースケース（議論で出たもの）

1. **source パターンで socket を切る**: 業務ごとに op vault を分けているなら `source = op://vault/*` で「その vault の全鍵」を 1 socket として切り出せる。現 filter（鍵種別/コメント/github 的属性）を **source glob まで拡張**。
2. **composite / 複数 upstream**: Composite Provider で複数 upstream（外部 agent も KeySource も）を 1 つに束ねる。
3. **複数 PW マネージャ対応時、列挙 ＞ probe**: op 以外（bitwarden 等）対応時、「各アプリの authsock を束ねて list を聞いて回り pubkey の在処を schema 横断で探す」より、**`[op://..., bw://...]` と source を明示列挙した Provider を定義する方がスマート**。probe 不要・宣言的。DR-0014 の「自動探索しない（データ→コード防止）」「config が source of truth」と一貫。
4. **単独 / 合成の両用**: 自己定義 Provider を単独で SSH_AUTH_SOCK として公開してもよいし、それを別 Endpoint の upstream として使い filter した socket を定義してもよい。

## 設計の詰めどころ

- **Identity メタdata スキーマ**: source filtering の前提。`Identity { pubkey, source_uri, namespace, comment, type }` を列挙時に載せる。
- **pubkey 列挙 と 秘密鍵 fetch の分離**: list は pubkey + メタのみ（安く常駐・cache 可）、秘密鍵 fetch は sign 時 lazy。→ **op-discovery-blocks-startup（起動時 op 同期ブロック）がこれで解消**。DR-0018 の force_eager も「pubkey 常駐・秘密 lazy」に整理。
- **selector 文法**: 鍵名 / source glob / 属性(type, comment 正規表現) / namespace の AND/OR。
- **dedup 優先順位**: 同一 pubkey が複数 Provider に居る時、どれが sign するか。
- **Composite の sign routing**: key blob → 所有 Provider を引いて振り分け。Keyring 投入鍵は必ずローカル署名（upstream に転送しない）。
- **ADD の脅威モデル**: write ベクトルは現 access-policy(DR-0012) が想定していない。注入を許す相手を sign/list と同じ `allowed_processes` で良いか、injection はより高権限に絞るか。
- **層の命名**: 「ssh-agent provider 層」＋「socket(endpoint, filter) 層」。Provider 名は ssh-adapter 内スコープなので多少の被りは許容だが上記の通り再考。

## スコープ注意

これは authsock を「op 公開 + upstream proxy の read-only relay」から「**source 列挙も upstream proxy も local 保持も合成できる ssh-agent provider toolkit**」へ広げる**ビジョン拡張**。full agent 代替を目指すかは要判断。本記録は idea 段階、実装着手前に DR で確定する。
