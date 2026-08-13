# draft-DR-0033: signed-by — code signature による entry owner principal と CRUD 認可

- Status: Draft (kawaz accept 待ち)
- Date: 2026-08-14
- 関連: draft-DR-0030 (kv per-entry peer-identity guard、本 DR は phase 2 の `signed-by` を
  「get constraint の追加」でなく **owner principal + CRUD 認可**として再定義する) /
  draft-DR-0034 (暗号化永続 vault、guard record と CAS version の永続化先。**相互参照必須**) /
  draft-DR-0031 (custom TouchID dialog、`guard_eval` の表示先) /
  DR-0012 (config 由来 `allowed_processes`、運用者宣言の gate) /
  DR-0024 (Store capability) / DR-0029 (snapshot handoff、record 引き継ぎ必須) /
  crate `macos-process-inspect` (SecCode API 追加が前提) /
  issue `2026-08-14-signed-by` (kawaz 裁定 18 項目) /
  research `2026-08-14-vault-design-tri-review.md` (3 系統レビュー統合、§1.3 / §1.4 が本 DR の入力)

## Context

llm-gateway の OAuth クレデンシャル Store バックエンドとして cache-warden を使う要件から、
DR-0030 が phase 2 に送っていた `signed-by` constraint が前倒しで必要になった。既存の 3
constraint (`same-user` / `same-ancestor` / `command=`) は DR-0030 §1b が明記するとおり
**同一 uid 内の誤爆・誤配線に対する区画化**であり、同一 uid の悪意あるコードには無力である
(`command=` は「$HOME に同名バイナリを置ける時点で回避可能」なラベルにすぎない)。OAuth
refresh token のように「同一 uid のマルウェアから守りたい」値には、コード署名という
OS が検証する identity を判定材料に据えた constraint が初めて意味を持つ。

環境変数 / 平文ファイル / Keychain がいずれも却下される理由も同じ軸で説明できる。環境変数は
子プロセスへ無差別に継承され `ps` / `/proc` 相当の経路で観測面が広い。平文ファイルは
same-uid の任意プロセスが読める。Keychain は ACL に signing identity を持てるが、cache-warden
が担いたい TTL・再認証・guard・regenerate といったライフサイクル制御を持たず、かつ
同一 uid のマルウェアがユーザ操作を装って許可を得る経路 (ユーザに TouchID を押させる) が
残る。cache-warden 側で per-entry に「この署名 identity だけが読める」を宣言できることが
本 DR の付加価値である。

3 系統レビュー (sol / fable / opus) は、この constraint を DR-0030 の枠に素直に足すと
**2 つの構造的な穴**が開くことを一致して指摘した。本 DR はその 2 点への回答を Decision の
中心に置く。

- **評価対象の穴** (§1.3): 祖先チェーンのどこかに一致を認める OR 判定にすると、署名済みの
  親 (Terminal / shell) の下の任意のコードが通ってしまう。
- **認可モデルの穴** (§1.4): DR-0030 の「set は record 全置換 / constraint なし set は
  record 削除」のまま signed-by を足すと、(a) 既知 key を別プロセスが先回りまたは上書き
  set して自分の signer を正本にできる confused-deputy 攻撃、(b) refresh のたびの set で
  signed-by を再宣言し忘れた 1 回で guard が silent に外れる footgun、が同時に生まれる。

## Decision

### 1. 評価対象は peer 直のみ — chain OR は採らない

判定材料は **control socket の接続 fd から取得した audit token** を
`SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` に渡して得た `SecCode` であり、
その **接続相手のプロセスそのもの**だけを評価する。祖先チェーンは一切見ない。

- **fd 由来の audit token を使う**: pid を経由すると評価と検証の間にプロセスが入れ替わる
  TOCTOU が成立する。fd キーの audit token は接続に対して race-free (DR-0030 §Security
  considerations と同じ根拠、`macos-process-inspect` crate doc)。
- **chain OR を採らない理由**: 「祖先のどこかに一致する署名があれば通す」は、署名済みの
  Terminal.app や IDE から起動された任意のバイナリを全部通す。同一 uid のマルウェアへの
  防御という本 DR の存在理由がそこで消える。DR-0030 の `same-ancestor` が chain を見るのは
  「同じセッション由来か」という**区画化**の問いであって、本 DR の「このコードは誰か」と
  いう**同一性**の問いとは判定の性質が違う。

#### 1a. 帰結 — CLI 経由の get では signed-by は成立しない

peer 直で評価する以上、`cw kv get` を挟むと peer は `cache-warden` CLI 自身になる。
CLI の署名 identity が記録された entry を llm-gateway が読むことはできず、逆に
llm-gateway の identity で守った entry を CLI から読むこともできない (これは仕様であって
不具合ではない)。したがって:

- **signed-by で守る entry の消費側は control socket を直叩きすることが前提条件**である。
  llm-gateway は Rust バイナリで credential Store を新規実装する段階にあり
  (`crates/llm-gateway/src/credential/file.rs` の平文 FileStore を置き換える作業がそのまま
  cw 連携になる)、この前提を最初から設計に織り込める (issue gate 2 で確認済み)。
- `cw kv get` からの読み取りが必要な entry に signed-by を宣言してはならない。CLI から
  読めないことを診断しやすくするため、拒否応答は落ちた constraint 種別として `signed-by`
  を返す (DR-0030 §4 の「種別のみ返す、setter identity は返さない」規定は維持)。

### 2. identity の正規形 — DR 文字列は受け取らず cw が組み立てる

designated requirement (DR) 文字列をユーザから直接受け取ると、綴り誤りが「常に真の緩い
requirement」に化ける事故が構造的に防げない (`anchor apple generic` の書き損じが典型)。
したがって cache-warden は **構造化入力を受け取り、DR 文字列を自分で組み立てる**。

| 入力フィールド | 意味 | 例 |
|---|---|---|
| `anchor` | 信頼アンカーの種別 | `apple-generic` (Developer ID / App Store 署名), `apple` (Apple 純正) |
| `team-id` | Developer Team ID | `XXXXXXXXXX` |
| `identifier` | codesign identifier | `com.example.llm-gateway` |

cw はこの 3 つから DR 文字列を組み立てて `SecCodeCheckValidity` の requirement とする
(`anchor apple generic and certificate leaf[subject.OU] = <team-id> and identifier
"<identifier>"` に相当する形。厳密な生成規則は実装時に固定し、生成済み文字列を
`kv list` / 診断ログに value-free で表示して監査可能にする)。

- **未知の anchor 種別・空文字列・想定外文字を含む team-id / identifier は set 時に
  `BadRequest`** で弾く (fail-loud)。DR 文字列を「そのまま渡せる escape hatch」は v1 では
  設けない — 設けた瞬間に上記の緩い requirement 事故が復活するため。
- **証明書ローテーションの契約**: Developer ID 証明書を更新しても team-id と identifier は
  不変なので、上記の正規形で組み立てた requirement は証明書更新を跨いで成立し続ける。
  逆に **Developer ID の失効は requirement 判定に反映されない** (`SecCodeCheckValidity` は
  既定では失効確認のためのネットワーク照会をしない)。「失効した証明書で署名された旧
  バイナリは通り続ける」ことを既知の限界として §4 の表に記載する。
- **helper の identifier 差**: 同一 team の helper プロセス (別 identifier) は別 principal
  として扱われる。helper から読ませたい場合は helper の identifier で別途宣言する必要が
  あり、team-id だけで identifier を省略する「同一 team なら全部通す」形は v1 では
  提供しない (緩さが不可視になるため)。

### 3. owner principal + CRUD 認可 — get constraint の単純追加ではない

signed-by を DR-0030 の constraint 列に 1 種足すだけにすると、§Context で挙げた
confused-deputy と guard 剥がれの 2 穴が開く。本 DR は signed-by を **entry の所有者
(owner principal)** として定義し、read だけでなく write / delete / 宣言変更まで認可の
対象にする。

#### 3a. create 時 TOFU で owner を確立

signed-by 宣言付きの set が、その key に **owner がまだ確立していない**状態で届いた場合、
宣言された principal をその entry の owner として確立する (Trust On First Use)。これは
key に対する最初の set (既存 record も既存値も無い) の場合だけでなく、**既に値や
DR-0030 constraint を持つが owner が無い entry への set** も含む — 後者も通常の全置換 set
として通り、その set が owner を確立する。

owner 無し entry への確立を許すことによる攻撃面の拡大は無い。owner が確立していない
entry は元々 same-uid の任意 peer が読み・上書き・削除できる状態にあり、そこに owner が
付くのは防御の追加であって剥奪ではないためである。逆にこれを禁止すると、攻撃者が key 名を
先回りして owner 無しの set を 1 回撃つだけで、正当な owner の確立を恒久的にブロックできる
DoS が成立してしまう。

既に owner が確立している key への set は §3b の認可を通る。

#### 3b. owner 確立後の CRUD 認可

| 操作 | 認可 |
|---|---|
| `get` (値の読み取り) | peer が owner requirement を満たすこと |
| `set` (値の更新) | 同上。**満たさない peer の set は AuthFailed で拒否** (先行/上書きによる owner 乗っ取りの遮断) |
| `del` / `undefine` (削除) | 同上 |
| owner の変更・除去 | 同上 (現 owner を満たす peer だけが owner を書き換えられる) |

これにより「既知の key 名を狙って別プロセスが先に set し、自分の signer を正本にして
以後の値を吸い上げる」経路が塞がる。owner を満たさない peer から見ると、guarded key は
読めず書けず消せない。

#### 3c. versioned update では guard を継承する — 無宣言 set で黙って外れない

DR-0030 §5 の「set は record の全置換、constraint なしの set は record を削除する」意味論は、
refresh のたびに set が走る用途では危険すぎる (再宣言を 1 回忘れた瞬間に guard が silent に
消え、以後 entry が無防備なまま生き続ける)。本 DR は signed-by を含む entry について
この意味論を上書きする:

- **owner が確立した entry への set は、signed-by 宣言を省略しても owner を継承する**。
  「宣言しない = 現状維持」であって「宣言しない = 解除」ではない。
- **owner の解除は明示操作でのみ可能**とする (`--clear-owner` 相当の明示フラグ。当然
  §3b により現 owner を満たす peer からしか実行できない)。
- signed-by 以外の DR-0030 constraint (`same-user` / `same-ancestor` / `command=`) の
  全置換意味論は**従来どおり変更しない**。継承するのは owner principal だけである。
  この非対称は「owner は entry の帰属を表す永続属性、他 constraint はその set 時点の
  実行文脈に紐づく宣言」という性質の違いに対応しており、DR-0030 の単純な意味論を
  壊さずに危険な silent 縮退だけを塞ぐ。

#### 3d. CAS との合成 (DR-0034 §refresh 調停)

DR-0034 が定める CAS 付き更新 (`expected_version`) は「更新の勝者を決める」機構、本 DR の
owner 認可は「更新してよい principal を決める」機構であり、直交する。評価順序は
**owner 認可 → CAS 検証 → 値の更新**とする (認可されない peer に version 情報を
与えないため。CAS 不一致応答は現行 version を返す性質があり、これを認可前に返すと
guarded entry の更新頻度が漏れる)。

### 4. 何を防ぎ、何を防がないか (DR-0030 §1b 形式)

`--help` / doc / `kv list` の表示にも同じ内容を載せる (DR-0030 が全 constraint に課した
明示義務を signed-by にも適用する)。

| 攻撃・状況 | 防げるか | 補足 |
|---|---|---|
| 同一 uid の**未署名**バイナリからの読み取り | **防げる** | requirement 不成立で拒否 |
| 同一 uid の**別 team / 別 identifier** 署名バイナリからの読み取り | **防げる** | 同上 |
| ad-hoc 署名 / 自己署名による identifier 詐称 | **防げる** | anchor 検証があるため identifier 一致だけでは通らない |
| $HOME 配下に同名バイナリを置く (`command=` を破る手口) | **防げる** | 署名検証は path に依存しない |
| **正規署名バイナリの代理実行** (owner 自身を攻撃者が起動し、その入出力を操る) | **防げない** | owner バイナリが外部入力どおりに秘密を渡す設計なら、cw から見て正当な要求と区別できない。owner 側が自分の入出力面を守る責務 |
| **インタプリタ経由** (owner が node / python スクリプトの場合、peer は インタプリタ) | **防げない** | 検証対象がインタプリタの署名になり `command=` と同強度に退化する。**前提条件 §5 で単一署名 Mach-O を要求することで回避する**。llm-gateway は Rust 単一バイナリのため非該当 (gate 2 確認済み) |
| **plugin / script の読み込み** (owner が外部コードを load する) | **防げない** | プロセス内に取り込まれたコードは owner の署名を纏う |
| **DYLD injection** (`DYLD_INSERT_LIBRARIES` 等) | hardened runtime + library validation が有効なら**防げる**、無効なら**防げない** | 前提条件 §5 |
| **侵害された旧バージョン**の owner バイナリ | **防げない** | 同一 identity なので requirement は成立する。version 下限を requirement に含める手段は v1 では提供しない (Open Q2) |
| **失効した Developer ID** で署名された旧バイナリ | **防げない** | §2 のとおり失効照会をしない |
| root / SIP 無効環境からの task port 経由の攻撃 | **防げない** | 脅威モデル外 (cache-warden 全体の前提と同じ) |
| CLI (`cw kv get`) 経由での読み取り | 通らない (§1a) | 防御ではなく仕様。設計上の制約として明示 |

### 5. 前提条件 — owner 側バイナリに要求する性質

以下が揃って初めて §4 の「防げる」列が成立する。揃わない対向に対して signed-by を宣言
しても、実効的な防御力は `command=` と大差ないラベルになる。

1. **単一署名 Mach-O** であること (インタプリタ実行でない、`command=` 相当への退化を防ぐ)
2. **hardened runtime** が有効であること (DYLD injection を防ぐ)
3. **library validation** が有効であること (署名外の dylib 読み込みを防ぐ)

kawaz 裁定 1 により、cache-warden 自身も含めローカルビルドも署名するフローが構築済みで
あるため、**未署名 dev build のための逃げ道は設計しない** (`signed-by` を宣言した entry は
未署名 peer に対して常に fail-closed で拒否する)。上記 2/3 の有効性を cw 側が実行時に
検証できるかは実装時に確認する (`SecCodeCopySigningInformation` の flags から
`kSecCodeSignatureRuntime` 等を読める見込み。読めるなら宣言時または評価時に警告を出す)。

### 6. surface

```
cw kv set FOO BAR --require-signed-by-anchor=apple-generic \
                  --require-signed-by-team=XXXXXXXXXX \
                  --require-signed-by-identifier=com.example.llm-gateway
```

- 3 フィールドは**同時指定**が必要 (部分指定は `BadRequest`)。「team だけ」「identifier
  だけ」の緩い宣言を文法レベルで作らない (§2)。
- wire (`Request::KvSet`) には `signed_by: Option<SignedByWire { anchor, team_id,
  identifier }>` を additive フィールドとして追加する。DR-0030 の `guard_constraints`
  とは**別フィールド**にする — owner principal は継承規則 (§3c) が constraint 列と違う
  ため、同じ列に混ぜると意味論が濁る。
- **positive ack を必須にする** (DR-0030 の `guard_applied` と同型): 旧 daemon は unknown
  フィールドを黙って捨てるため、ack が無い応答を受けた CLI は「owner 無しで値だけが
  無防備に残った」と判断し、値を best-effort で削除してエラーにする。
- `kv list` / `status` は owner の有無と組み立て済み requirement 文字列を value-free で
  表示する。
- 非 macOS では `signed-by` は評価不能 = **fail-closed 拒否** (DR-0030 の非 macOS 規定と
  同じ)。宣言自体も set 時に `BadRequest` で拒否する (保存できるが永久に読めない entry を
  作らせない)。

### 7. 永続化 — DR-0034 vault との相互参照

owner principal は entry の帰属を表す永続属性であり、**値が cold start を越えて復活する
経路では owner も必ず一緒に復活しなければならない**。値だけが戻って owner が消える縮退は
「認可が黙って消える」最悪方向であり、DR-0030 §3 がダウングレード規定で塞いだのと同型の
問題である。

- **snapshot (DR-0029 graceful restart)**: DR-0030 §3 の規定に従い、owner 付き entry が
  含まれる export は format_version を上げてダウングレードを cold start に退化させる。
- **vault (DR-0034)**: 永続 entry の owner record と CAS version は **vault format に
  含める** (DR-0034 §vault format)。vault 側で owner を落とす実装は本 DR 違反とする。
- どちらの経路でも、**owner を復元できない場合は値も復元しない** (fail-closed)。

## セキュリティ整理

| 脅威 | 対策 / 評価 |
|---|---|
| pid 経由の TOCTOU | fd の audit token から `SecCode` を取得 (§1)。pid は判定材料に使わない |
| 署名済み親からの間接読み取り | chain OR を採らず peer 直のみで評価 (§1) |
| owner 乗っ取り (先行 set / 上書き set) | create 時 TOFU + owner 確立後の write/delete 認可 (§3a/3b) |
| guard の silent 剥がれ | owner は versioned update で継承、解除は明示操作のみ (§3c) |
| 緩い requirement の誤記 | DR 文字列を受け取らず構造化入力から組み立て、未知値は fail-loud (§2) |
| 拒否経路からの情報漏洩 | 拒否は constraint 種別のみ返し setter identity を返さない (DR-0030 §4 を継承)。拒否は再認証 / TouchID / regenerate / backoff を一切トリガしない |
| owner 認可前の CAS 情報漏洩 | owner 認可 → CAS 検証の順 (§3d) |
| 旧 daemon への mixed-version 送信 | positive ack 必須、ack 無しなら CLI が値を削除してエラー (§6) |
| cold start での認可消失 | snapshot / vault の双方で owner 同伴を必須化、復元不能なら値も捨てる (§7) |

## Alternatives (不採用)

- **chain OR (祖先のどこかに一致を認める)**: 署名済み Terminal / IDE 配下の任意コードが
  通り、同一 uid のマルウェアへの防御という存在理由が消える (§1)。
- **DR 文字列の直接受け取り**: 綴り誤りが「常に真の requirement」に化ける事故を構造的に
  防げない (§2)。表現力は上がるが、その表現力を必要とする用途が v1 に無い。
- **`signed-by` を DR-0030 の constraint 列に 1 種足すだけ**: confused-deputy と guard
  剥がれの 2 穴が開く (§Context、tri-review §1.4)。
- **team-id のみでの宣言 (identifier 省略)**: 同一 team の全バイナリが通る緩さが宣言から
  読み取れない。必要になれば明示的な wildcard 構文として別途設計する。
- **未署名 dev build のための逃げ道 (環境変数での bypass 等)**: kawaz 裁定 1 でローカル
  ビルドも署名するフローが確立済みのため不要。bypass 経路は攻撃者にとっても bypass 経路。
- **Keychain の ACL に signing identity を持たせて代替する**: TTL / 再認証 / regenerate /
  guard といったライフサイクル制御を持たず、cache-warden の他機構と合成できない (§Context)。

## Open Questions

1. **hardened runtime / library validation の実行時検証**: `SecCodeCopySigningInformation`
   の flags から前提条件 §5 の 2/3 を cw が実際に読めるか、読めた場合に「宣言時に警告」
   「評価時に拒否」のどちらに倒すか。実装時の実機確認が必要 (読めるなら評価時拒否まで
   倒したいが、helper 等の正当な例外が出るなら警告止まりが安全)。
2. **バージョン下限の requirement 化**: 「侵害された旧バージョンの owner バイナリ」(§4) を
   防ぐには requirement に version 条件を含める必要があるが、更新のたびに全 entry の
   宣言を書き換える運用が発生する。v1 では既知の限界として明示するに留め、必要性が
   実運用で確認できてから設計する。
3. **owner 解除フラグの命名と CLI 形状**: §3c の明示解除操作を `kv set --clear-owner` と
   するか独立サブコマンド (`kv owner clear`) とするか。DR-0030 の flag 群との一貫性を
   見て実装時に決める。
4. **`macos-process-inspect` への API 追加範囲**: `SecCodeCopyGuestWithAttributes` +
   `SecCodeCheckValidity` + `SecCodeCopySigningInformation` を crate 側にどう切るか
   (raw に近い薄い wrapper か、requirement 組み立てまで crate に持たせるか)。crate は
   汎用ライブラリなので requirement 組み立て (cache-warden のドメイン判断) は cw 側に
   置くのが筋、という前提で起草しているが crate 側の設計と合わせて確定する。
