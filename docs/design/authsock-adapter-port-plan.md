# authsock アダプタ移植計画ドラフト

> Status: ドラフト（kawaz レビュー前の検討資料。DR / INDEX / DESIGN には未反映）
> Date: 2026-06-10
> 前提 DR: DR-0003（セキュア KV コア + アダプタ）、DR-0004（authsock-warden 後継・吸収）、
> DR-0008（単一デーモン直担）、DR-0009（control socket protocol v1）、DR-0010（TOML config + 再認証コマンド）

この文書は authsock-warden（SSH agent proxy + 鍵セキュリティ製品）の資産を
cache-warden 上の「authsock アダプタ」として移植する計画の検討材料である。
DR-0004 が初期方針として示した「コア vs アダプタ」の振り分けを、実コードレベルに
具体化する。確定事項ではなく、kawaz レビューの叩き台。

調査ベースで書く。authsock-warden の仕様は読み取れた範囲のみ記述し、不明点は「不明」と明記する。

---

## 0. 用語と現状把握（調査結果）

- **cache-warden コア** = lib crate `cache-warden`（`crates/cache-warden/src/`）。
  純粋ドメイン。`Store` / `CacheEntry` / `EntryState`(Active/SoftExpired/HardExpired) /
  `Ttl`(soft/hard 2 段) / `SecretBytes`(mlock + zeroize) / `ValueSource`(Static/Command) /
  `CommandRunner` / `Authenticator`+`CommandAuthenticator` / `ProcessInspector`+`SystemInspector` /
  `ProcessInfo`(pid/ppid/path/start_time)。**socket / async / daemon を一切持たない**（lib doc 明記）。
  依存は `zeroize` + `libc` のみ（DR-0002/0005/0006）。
- **cache-warden CLI/daemon** = `crates/cache-warden-cli`。tokio 単一プロセス（DR-0008）。
  control socket（JSON Lines、DR-0009）+ TOML config + 再認証コマンド配線（DR-0010）。
  `daemon/server.rs`（bind / accept / `spawn_blocking` で同期ハンドラ隔離）、
  `daemon/handler.rs`（`Store` への純粋ディスパッチ）、`daemon/peer.rs`（peer pid）、
  `protocol/wire.rs`（Request/Response）。依存に `tokio` / `serde` / `serde_json` / `base64` / `toml` / `libc`。
- **authsock-warden** = 別 crate `authsock-warden`（`src/`）。SSH agent proxy。
  `protocol`（SSH agent codec/message）、`agent`（server/upstream/proxy/warden_proxy）、
  `filter`（鍵フィルタ群）、`keystore`（op/signer/registry/secret/timer/cache）、
  `policy`（process/engine）、`config`、`security`。依存に `ssh-key` / `bytes` /
  `ed25519-dalek` / `rsa` / `pkcs8` / `tokio` / `tracing` / `serde` 等。

> **重要な前提（DR-0003 の確定事実）**: authsock-warden 側の soft/hard TTL・再認証・KV は
> **未実装**。実装済みなのは 4 状態ライフサイクル（`KeyRegistry`）と SSH proxy / op 署名。
> ただし調査の結果、後述の通り **`KeyRegistry` は warden_proxy から配線されていない**
> （warden_proxy は独自の `OpManagedKey` + per-key `cached_pem` Mutex を使い、registry を経由しない）。
> = 「未配線コア」は warden 側にもある。これが移植マッピングの肝になる。

---

## 1. 資産の棚卸しと移植マッピング

### 1.1 全体方針

DR-0004 の初期振り分け（コア: TTL/プロセス認証/再認証/メモリ保護、アダプタ: SSH protocol/
鍵フィルタ/1Password 署名/鍵ライフサイクル）を踏襲する。**コアは cache-warden 側に既に実装済み**
なので、移植は基本「アダプタ部分を cache-warden に持ち込み、コアの再実装を捨てる」方向になる。

新規 crate を 1 本追加する想定（DR-0002 の workspace 分離パターンに沿う）:

| crate | 役割 | 主依存 |
|---|---|---|
| `cache-warden`（既存 lib） | コア。変更最小。署名 trait の口だけ足す可能性あり（§3 で論点化） | zeroize, libc |
| `cache-warden-authsock`（**新規 lib**） | authsock アダプタ。SSH agent protocol codec / 鍵フィルタ / op 署名 / 鍵発見 | ssh-key, bytes, ed25519-dalek, rsa, pkcs8, zeroize |
| `cache-warden-cli`（既存） | daemon。authsock アダプタの listener task を足す | 上記 + tokio |

> 配置の代替案（不明点）: アダプタを lib にするか CLI 内モジュールにするか。lib 案を推す根拠は
> 「コアの依存最小ポリシー（DR-0002）を守りつつ、ssh-key 等の重い依存をアダプタ crate に隔離できる」。
> ただし DR-0008 が「全アダプタは同一プロセス内 listener task」と定めており、アダプタの async 配線は
> CLI 側に残る。lib に純粋ロジック（codec / filter / signer / 発見）、CLI に listener という分割が素直。
> **確定 (2026-06-11 kawaz)**: 上表の 3 crate 構成（コア lib / authsock アダプタ lib / cli バイナリ）で確定。
> プロセスは単一のまま（DR-0008 維持）。接点規約: アダプタは `SecretBytes` を所有せず短命借用のみ、
> `expose_secret()` が唯一の grep 可能な露出点、コアの `Mutex` 下でのみ秘密値に触る（§3 判断 1 参照）。

### 1.2 モジュール対応表（warden → cache-warden）

| warden モジュール | 行き先 | 扱い | 根拠 |
|---|---|---|---|
| `protocol/message.rs`（`AgentMessage`/`MessageType`/`Identity`/`SignRequestFields`/codec） | **アダプタ** | **そのまま移植** | SSH agent protocol は鍵種別固有（DR-0004）。cache-warden に同等物なし。自前 codec は完成度が高く ssh-agent crate 依存より移植が安全（§3 論点） |
| `protocol/codec.rs`（`AgentCodec` read/write） | アダプタ | そのまま移植 | 同上 |
| `agent/upstream.rs`（upstream agent 接続） | アダプタ | そのまま移植 | proxy 転送（agent member）に必須 |
| `agent/warden_proxy.rs`（`WardProxy`: REQUEST_IDENTITIES 集約 + SIGN ルーティング） | アダプタ | **移植 + 改修**（鍵キャッシュ部分をコア `Store` に置換、§1.4） | アダプタの中核ロジック。ただし `OpManagedKey.cached_pem` のキャッシュ責務はコアへ移す |
| `agent/proxy.rs`（基本 proxy。authsock-filter 由来の単純フィルタ転送） | アダプタ | 移植 or 廃止検討 | `WardProxy` が機能を包含（design.md 末尾）。並走最小化のため最初は移植不要、後で要否判断 |
| `agent/server.rs`（UnixListener bind + accept loop） | **移植不要（置換）** | cache-warden の `daemon/server.rs` の bind/accept パターンに統合 | DR-0008「全 listener は同一プロセス内 task」。cache-warden 側に bind_control_socket / serve がすでにある（umask 0600 + stale 検出も実装済み）。socket ごとに listener task を生やす形へ一般化 |
| `filter/*`（comment/fingerprint/github/keyfile/keytype/pubkey/rule/evaluator） | **アダプタ** | そのまま移植 | 鍵フィルタは SSH 鍵種別固有（DR-0004）。`FilterEvaluator`（OR of AND）はそのまま使える |
| `keystore/signer.rs`（PEM → 署名、Ed25519/RSA、PKCS#8 lenient） | **アダプタ** | **そのまま移植** | 1Password ローカル署名（DR-0004 でアダプタ確定）。stateless adapter として既に設計済み（doc 明記）。DR-015 の RSA PKCS#8 / SHA2 フラグ分岐込み |
| `keystore/op.rs`（op CLI: list/get_public_key/get_private_key） | アダプタ | そのまま移植 | op 連携は SSH 鍵固有。ただし PEM 取得は将来コアの `CommandRunner` 経由に寄せる余地あり（§1.4 論点） |
| `keystore/cache.rs`（op_map.json ディスクキャッシュ） | アダプタ | そのまま移植 | op 鍵発見（DR-011）の一部。鍵種別固有 |
| `keystore/registry.rs`（`KeyRegistry`/`ManagedKey`/4 状態） | **大半は置換（コアへ吸収）** | §1.3 参照。`KeySource` 列挙等の薄い部分のみアダプタに残す可能性 | DR-0004「鍵ライフサイクル = アダプタ」だが、状態機械の実体はコアの `CacheEntry` 2 段 TTL で表現する（§1.3） |
| `keystore/secret.rs`（`SecretKeyData` zeroize） | **移植不要（置換）** | コアの `SecretBytes`（mlock + zeroize + Debug redaction）に置換 | コアの方が高機能（mlock あり）。DR-0004「メモリ保護 = コア」 |
| `keystore/timer.rs`（`KeyTimer`: timeout/forget_after） | **移植不要（置換）** | コアの `Ttl` + `Monotonic`/`Clock` に置換 | DR-0004「TTL = コア」。warden の `loaded_at`/`last_used` 2 軸は §1.3 でマッピング検討 |
| `policy/process.rs`（`ProcessChain`/peer_pid/`ProcessInfo`） | **大半は置換（コアへ）** + アダプタに `matches_any` | コアの `ProcessInspector`/`SystemInspector`/`ProcessInfo` + CLI の `peer.rs` に置換。`matches_any`(allowed_processes 照合) はポリシー解釈なのでアダプタに残す | DR-0004「汎用プロセス認証 = コア、ポリシー解釈 = アダプタ」。コアの `ProcessInfo` は pid/ppid/path/start_time のみ（uid/gid/cwd/argv は意図的に省略） |
| `policy/engine.rs`（3 層ポリシー: keys ∩ socket） | **アダプタ** | 移植（パリティ達成フェーズで） | DR-0004「ポリシー解釈 = アダプタ」。コアは process chain を運ぶだけでポリシー判定しない（auth.rs doc 明記） |
| `security/anti_debug.rs`（ptrace/DYLD 検出） | アダプタ or CLI | 移植（後期フェーズ） | DR-0004「anti-debug = コア」と書かれているが、cache-warden コアにはまだ無い。プロセス全体の保護なので CLI（daemon 起動時）に置く方が素直か。**配置は要判断** |
| `security/memory.rs`（mlock） | **移植不要（置換）** | コア `SecretBytes::mlock` に吸収済み | コアで実装済み |
| `config/*`（sources/sockets/keys/3 層） | **アダプタ用 config として CLI に追加** | §3 で論点化（warden config 互換にするか） | cache-warden の config は `[daemon]`/`[auth]`/`[kv.*]` のみ。authsock 節を足す必要 |
| `cli/*`（clap args/commands） | CLI | 一部移植 | `run` に authsock socket 群の起動を足す。サブコマンド体系は cache-warden 側（DR-0009）に合わせる |
| `utils/socket.rs`/`path.rs` | CLI | 必要分のみ移植 | path 展開等。cache-warden の `expand_tilde` は最小実装なので warden の `expand_path`（$VAR 対応）を取り込む余地 |

### 1.3 焦点 (a): 4 状態 → 2 段 TTL + 再 set のマッピング

DR-0004 の核心論点。warden の `KeyState`(NotLoaded/Active/Locked/Forgotten) を
cache-warden コアの `EntryState`(Active/SoftExpired/HardExpired) + 再 set でどう表現するか。

**まず重大な調査結果**: warden の `KeyRegistry`（4 状態の実体）は **`WardProxy` から配線されていない**。
`warden_proxy.rs` は `OpState::Ready { keys: HashMap<Bytes, OpManagedKey> }` を独自に持ち、
署名時は `OpManagedKey.cached_pem: Arc<Mutex<Option<Zeroizing<String>>>>` を直接使う。
`registry.rs` の lock/unlock/forget/check_timers は warden_proxy のコードパスから呼ばれていない
（grep 範囲では `registry` の利用は `keystore::mod` の re-export のみで、proxy は未使用）。
→ **つまり「4 状態ライフサイクル」は warden でも実質「メモリにある(cached_pem=Some)/ない(None)」の
2 状態しか動いていない**可能性が高い（lock/forget のタイマー駆動が proxy に繋がっていない）。
**この点は実機の `run` 経路を追って要確認（不明）**。もしそうなら、4 状態の完全移植は不要で、
「未配線の設計意図」をコアの 2 段 TTL で**初めて実配線する**のが移植のゴールになる。

状態対応（設計意図ベース）:

| warden `KeyState` | cache-warden 表現 | メモ |
|---|---|---|
| **NotLoaded**（鍵を知っているが未ロード） | エントリ未登録 or `ValueSource::Command` で値未取得 | cache-warden は「値が無いと set できない」。公開鍵だけ知っている状態（= 署名に応じられるが秘密鍵は未取得）はコアに直接の対応概念が無い。**ギャップ**（§1.3 末尾） |
| **Active**（メモリにあり署名可） | `EntryState::Active` | soft TTL 内 |
| **Locked**（メモリにあるが署名不可、re-auth 待ち） | `EntryState::SoftExpired` | soft TTL 切れ。`get` がゲートされ、`extend_authenticated`（再認証）で Active へ復帰。warden の `on_timeout="lock"` + unlock に対応 |
| **Forgotten**（zeroize 済み、再取得に TouchID） | `EntryState::HardExpired`（command 型なら `regenerate` で再生成） | hard TTL 切れ。warden の `on_timeout="forget"` / `forget_after` に対応。command 型 = op item get 再実行で再生成（コア `Store::regenerate` がまさにこれ） |

タイマー軸の対応:

| warden `KeyTimer` | cache-warden `Ttl` |
|---|---|
| `timeout`（last_used から、is_timed_out → Locked） | `soft`（activated_at から、SoftExpired） |
| `forget_after`（loaded_at から、should_forget → Forgotten） | `hard`（activated_at から、HardExpired） |

**ギャップ分析**:

1. **タイマー基準点の差**: warden の `timeout` は `last_used`（署名のたび `touch()` でリセット）= **アイドルタイムアウト**。
   一方コアの soft TTL は `activated_at`（`extend`/`set`/`regenerate` でのみリセット）= **絶対タイムアウト**。
   署名のたびに soft 窓を延ばす挙動がコアに無い。
   - 対応案 A: アダプタが署名成功のたびにコアの `extend`（auth 無しの window refresh、`Store::extend` あり）を呼ぶ。
     `extend_authenticated` は Active なら auth 無しで window refresh する仕様なので、これで「使うたび延命」が再現できる。
   - 対応案 B: アイドル概念を捨て、絶対タイムアウトに寄せる（仕様変更）。kawaz 判断事項。
   - **論点**: warden 実機がアイドル(`touch`)を本当に使っているか不明（registry 未配線疑惑と同根）。要実機確認。

2. **`forget_after` が loaded_at 基準**: warden は forget_after を loaded_at（初回ロード）から測り、
   refresh でリセット。コアの hard TTL も activated_at 基準で `regenerate`/`set` でリセットなので概ね一致。
   ただし「lock してメモリ保持のまま forget_after だけ進む」挙動（Locked のまま hard 到達）は
   コアでは「SoftExpired のまま hard TTL 到達 → HardExpired」で自然に表現できる（`state()` が
   hard を soft より優先評価する実装を確認済み）。**ギャップ小**。

3. **NotLoaded（公開鍵は見せるが秘密鍵未取得）のギャップ**（最重要）:
   SSH agent の REQUEST_IDENTITIES は「秘密鍵をロードせずに公開鍵一覧を返す」のが本質。
   warden_proxy はこれを「op item list/agent で公開鍵 blob だけ集め、SIGN 時に初めて op item get」で実現。
   cache-warden コアの `Store` は「値（= 秘密鍵 PEM）を持つエントリ」しか扱えず、
   「公開鍵だけ知っていて値は遅延取得」を直接表現できない。
   - 対応案: アダプタ側に **公開鍵レジストリ**（key_blob → 取得方法）を持ち、コア `Store` には
     「初回 SIGN で取得した秘密鍵 PEM」だけをキャッシュする。つまり:
     - REQUEST_IDENTITIES: アダプタの公開鍵レジストリから返す（コア未関与）。
     - SIGN: コア `Store.get(key_blob)` がヒットすれば即署名。ミス（NotLoaded 相当）なら
       `ValueSource::Command`（= `op item get ...` 相当）で取得 → コアに `set` → 署名。
       hard 切れ後の再取得は `Store::regenerate` がそのまま担う。
   - これは warden_proxy の現状（`OpManagedKey`=公開鍵側メタ、`cached_pem`=秘密鍵キャッシュ）と
     **構造が一致**。`cached_pem` の Mutex キャッシュをコア `Store`（key_blob をキーにした KV）に置換すれば、
     mlock / 2 段 TTL / 再認証 / 再生成がタダで効く。**これが移植の本丸**。
   - **残るギャップ**: SSH の鍵識別子は「公開鍵 blob（バイナリ）」。コア `Store` のキーは `String`。
     key_blob を base64 等で String 化してコアキーにするか、コアキーを `Vec<u8>` 許容に拡張するか。
     軽微だが要判断（§3 実装判断）。

### 1.4 焦点 (b): op 鍵発見（DR-011 の 4 段キャッシュ）の住所

DR-011 の発見戦略（ディスクキャッシュ → op item list → agent socket 照合 → op item get 並列）は
**アダプタに住む**。根拠:

- 発見対象は「SSH 公開鍵 ↔ 1Password itemid」のマッピングで、SSH 鍵種別と 1Password に固有。
  コア（汎用 KV）はこの語彙を持たない（DR-0004「鍵ライフサイクル = アダプタ」）。
- ディスクキャッシュ（op_map.json, fingerprint→itemid）は SSH fingerprint という鍵固有概念。
- agent socket 照合（REQUEST_IDENTITIES で fingerprint マッチ）も SSH agent protocol 固有。

**ただしコアと接する境界**:
- 発見の成果物 = 「key_blob → 取得コマンド（op item get itemid）」のマップ。これはアダプタが保持。
- 秘密鍵の**遅延取得とキャッシュ**だけがコアに乗る（§1.3 案）: アダプタは itemid を
  `ValueSource::Command(["op","item","get",itemid,"--fields","private_key","--reveal",...])` に変換して
  コアに渡し、コアが `CommandRunner` で実行 → `SecretBytes` 化 → TTL 管理。
- これにより warden の `op::get_private_key`（同期 `Command`）は、コアの `CommandRunner` に**置換できる**
  （コアは spawn_blocking 隔離 + timeout + stderr redaction + 改行トリム済み）。
  - 論点: warden の `op::get_private_key` は JSON で `--format json` を読んで `.value` を抽出する。
    コアの `CommandRunner` は stdout 生バイトをそのまま値にする。op が JSON を返すので、
    そのままだと値が JSON 文字列になる。→ アダプタが `op ... --format json | jq -r .value` 相当の
    後処理を挟むか、`--reveal`（プレーン出力）で JSON を介さず取得するか。**実装判断**。
- `op item list`（TouchID を引きうる）と agent 照合は発見フェーズの処理で、コアの再認証(soft 切れ)とは別物。
  ここはアダプタが従来通り spawn_blocking で回す。

### 1.5 焦点 (c): 1Password ローカル署名（signer）の置き場所

**アダプタに住む**（DR-0004 で確定済み、異論なし）。`keystore/signer.rs` は既に stateless adapter
（PEM 文字列を受け取り署名 blob を返す、状態を持たない）として設計され、doc に
「a future KV / cache-warden migration drops in cleanly」と明記されている。移植は機械的:

- `signer::sign(pem, data, flags) -> Vec<u8>` をアダプタ crate にそのまま移す。
- 呼び出し側（warden_proxy の `sign_with_op`）の `cached_pem` 参照を「コア `Store.get(key_blob)` で
  得た `SecretBytes`（= PEM bytes）を `expose_secret()` で借りて `signer::sign` に渡す」に置換。
- 依存（ed25519-dalek / rsa / pkcs8 / sha1/sha2 / ssh-key）はアダプタ crate の依存になる。
  コア（cache-warden lib）には**持ち込まない**（DR-0002 依存最小を維持）。
- DR-015（RSA PKCS#8 + SHA2 フラグ）と 1Password non-canonical Ed25519 lenient parse もそのまま移植。

> 論点（§3）: 署名フックをコアの trait にするか。コアは「値を返す KV」までが責務で、
> 「値で署名する」はアダプタの仕事。コアに署名 trait を生やすのは責務逸脱（design-thinking
> ルールの「従の都合で主を歪めない」）。**コアは触らず、署名はアダプタが `SecretBytes` を借りて行う**を推す。

---

## 2. 段階的移植の iteration 分割案

DR-0004 の移行 Phase（0 現状 / 1 並走 / 2 パリティ / 3 切替 / 4 引退）の **Phase 1 並走** に
到達するまでを、実装 iteration に割る。各 iteration は cache-warden 側で完結し、
authsock-warden は一切触らない（DR-0004「authsock リポは保守のみ」）。

### Iteration -1: 前提コア修正（タイマー 2 基準分離 + pin）✅ 完了（DR-0011）

アダプタ着手前に済ませるコア側修正（§3 判断 3 の確定を実装に落とす）。**実装済み（DR-0011）**。

> **注記**: 当初の「明示の hard 延長 API（`kv extend KEY --hard 8h` 相当）」は、
> **`kv pin` として実装**した。`--hard 8h`（hard を N 時間延ばす）より、`pin_until(deadline)`
> （指定期限まで失効抑止）の方が「T までは止めないでほしい」というユーザ意図に正確で、既に経過した分との
> 合算に悩まなくて済むため（DR-0011 Alternatives 案 A 参照）。pin は **再認証必須**（Active からでも要求、
> extend と非対称）、`unpin` で解除（認証不要）。

- スコープ（実装済み）:
  - コアの TTL 基準を `loaded_at`（set/regenerate で固定、hard の基準）と `extended_at`（extend で動く、
    soft の基準）の **2 基準に分離**。「extend が `activated_at` をリセットして hard まで動く」曖昧
    仕様を解消。`extend` は `extended_at` だけを動かし、`loaded_at`(hard 基準) は触らない。
  - **pin API**（`CacheEntry::pin_until` / `Store::pin_authenticated` / `kv pin <KEY> <DUR>`）を追加。
    指定期限まで soft/hard とも失効抑止。`loaded_at` を直接ずらすのではなく「期限まで判定を抑止」する形。
- 依存: なし（コア単独、authsock より前）。
- 検証（達成）: 既存 entry/store テストを 2 基準前提に更新 + idle extend で soft だけ伸びて hard は固定、
  pin 期限ちょうど / pin 中に本来の hard 超過 → pin 切れで即 HardExpired / HardExpired への pin 拒否 /
  再 pin / unpin を単体・handler・E2E で確認。`just ci` 全通過。

### Iteration 0: アダプタ crate の骨格 + SSH agent protocol codec ✅ 完了（2026-06-11）

- スコープ: 新規 crate `cache-warden-authsock` を切り、`protocol/message.rs` + `codec.rs` を移植。
  `AgentMessage` / `MessageType` / `Identity` / `SignRequestFields` / encode/decode / `AgentCodec` read/write。
- 依存: `ssh-key`(0.6), `bytes`, `thiserror`, `tokio`(io-util のみ)。署名系 (rsa / ed25519-dalek 等) は次 iteration へ。
- 検証: warden の protocol テスト（roundtrip / truncated / oversized / max_count）を移植 + 境界テスト追加
  （未知 message type / 不正長 / 途中切断 / flags 既定値 / wire 固定バイトベクタ）。`just ci` 全通過。
- 依存関係: なし（先頭）。
- 実績:
  - 純粋部（`message.rs`）と async I/O（`codec.rs`）を分離。純粋部は同期テスト、codec は `#[tokio::test]`。
  - エラー型は warden の巨大共通 Error を本 iteration で使う 2 バリアント（`InvalidMessage` / `Io`）に縮小。
  - `parse_identities` / `parse_sign_request_key` のインライン読込を既存 `read_size_prefixed` に統一
    （ロジック互換のリファクタ。エラー文言が "too short" → "length missing" に変わる箇所はテストも追従）。
  - `tests/wire_vectors.rs` で REQUEST_IDENTITIES / IdentitiesAnswer / SIGN_REQUEST / SIGN_RESPONSE の
    wire 固定バイト列を pin（warden が実装する draft-miller-ssh-agent framing との一致を証明）。
  - テスト: authsock 37（unit 32 + wire ベクタ 5）、いずれも green。コア側既存テストにも回帰なし。

### Iteration 1: 最初の動く milestone — 「socket 1 本 listen + KV の秘密鍵で署名」✅ 完了（2026-06-11）

- スコープ（プロンプト想定の milestone を採用、妥当性を §2 末尾で検討）:
  - `daemon run`（旧 `run`、CLI 再構成で `daemon` グループへ移動）に **authsock listener task** を
    1 本足す（DR-0008 の同一プロセス内 task）。
  - その socket は **static な秘密鍵 1 本**を cache-warden コア `Store` に `kv set`（PEM を value）した
    エントリに対して、SSH agent protocol で REQUEST_IDENTITIES（公開鍵 1 個を返す）+ SIGN_REQUEST に応える。
  - 署名はアダプタの `signer::sign`（Ed25519 から。RSA は Iteration 後送り可）。
  - upstream / op / filter / policy は**まだ無し**。
- 依存: Iteration 0（codec） + コア `Store`/`SecretBytes`/`CommandRunner`（既存）+ `signer` 移植。
- 検証:
  - `ssh-add -L`（= REQUEST_IDENTITIES）でその socket から公開鍵が見える。
  - `SSH_AUTH_SOCK=<その socket> ssh-keygen -Y sign` 相当 or 実 ssh で署名が通る。
  - コアの 2 段 TTL を effective に: soft 切れ → 再認証コマンド（`[auth].command`）→ Active 復帰、
    hard 切れ → 再取得（command 型なら）を実機で 1 ケース確認。
- **milestone 妥当性**: 妥当。理由 = (1) SSH agent protocol の最小経路（identities + sign）と
  コア KV/署名の結線が、移植で最も不確実な「公開鍵レジストリ ↔ コア KV ↔ アダプタ署名」の三者結線を
  最小構成で検証できる。(2) op / filter / policy は独立に積み増せる直交機能なので、後続 iteration に
  切り出せる。(3) この時点で「別ソケットで並走」の足場（listener task 化）が揃う。
  - 補足: static 鍵で始めるのは、op 発見（DR-011、TouchID / 並列 / キャッシュ）の複雑さを
    後段に隔離できるため。最初から op だと検証の不確実性が二重になる。
- 実績（2026-06-11）:
  - **signer 移植**（`cache-warden-authsock/src/signer.rs`）: warden の `keystore/signer.rs` を
    そのまま移植（Ed25519 + RSA、PKCS#8 lenient、DR-015 の SHA2 フラグ分岐、1Password
    non-canonical Ed25519 抽出）。`tracing` は外し cache-warden 流の最小ログ（ssh-rsa SHA1 警告のみ
    `eprintln!` 1 回）。`sign(pem, data, flags)` は `&str` を借りて署名 blob を返すステートレス API。
    エラー型に `KeyStore` バリアントを追加（秘密値を含まない固定文言）。
  - **公開鍵レジストリ**（`registry.rs` + signer の `public_key_blob_from_pem`）: key_blob（wire 形式）
    → `{ comment, kv_key }` の `BTreeMap`。公開鍵は秘密鍵 PEM から導出（signer の `KeyMaterial` を
    再利用し 1Password lenient 経路も共有）。daemon 起動時に一度だけ導出して保持（秘密値はレジストリに
    残さず公開鍵 blob のみ）。`identities()` が REQUEST_IDENTITIES 応答を返す。
  - **config 新節**（`[authsock.sockets.NAME]` = `path` + `keys`）: `deny_unknown_fields`、起動時
    バリデーション（空 path / 空 keys を拒否）。`Config::authsock_sockets()` で取得。
  - **daemon 統合**（`cache-warden-cli/src/daemon/authsock.rs`）: socket ごとに listener task を追加
    （control socket と同じ `bind_control_socket`= 0600 / stale 復旧 / 二重起動拒否 / shutdown watch 共有）。
    接続処理は `AgentCodec` で読み、REQUEST_IDENTITIES → レジストリ応答 / SIGN_REQUEST → レジストリで
    key_blob → kv_key 引き → `Store` から認証ゲート経由（SoftExpired は `extend_authenticated`、
    HardExpired+command は `regenerate`、peer pid → ancestry を requester に）で PEM 取得 → signer 署名 →
    **成功時 `extend` で idle 延命**（DR-0011）。失敗・拒否・未知鍵・不正要求はすべて SSH_AGENT_FAILURE
    （payload 空 = 詳細を漏らさない）。ハンドラは control socket と同じく `spawn_blocking` 隔離。
  - **検証**: 単体（signer 移植テスト + registry + daemon ハンドラ 9 件: identities / 署名検証 /
    未知鍵 FAILURE / DenyAll FAILURE / soft extend / hard static FAILURE / idle 延命）+ E2E
    （`tests/authsock_e2e.rs`: 実 `ssh-keygen` で Ed25519 生成 → config の command プリロードで KV 投入 →
    daemon 起動 → `SSH_AUTH_SOCK=<sock> ssh-add -l` で公開鍵列挙 → 生 wire の SIGN_REQUEST → 署名を
    `ssh-key` crate で verify / DenyAll 時 FAILURE + payload 空）。`just ci` 全通過、既存テスト回帰なし。
  - **brief から変えた点**: なし（milestone 通り）。RSA は signer に移植済みだが、Ed25519 鍵で E2E を
    回し署名パスを実証（RSA も単体テストで検証済み）。

### Iteration 2: upstream proxy member（agent 転送）✅ 完了（2026-06-11）

- スコープ: `agent/upstream.rs` 移植。socket の `upstreams` を upstream に転送。
  REQUEST_IDENTITIES で upstream の鍵も集約、SIGN を upstream にルーティング（warden_proxy の
  `SigningBackend::Agent` 経路）。
- 依存: Iteration 1。
- 検証: 1Password agent socket を upstream に指定し、その鍵で署名が通る（warden と挙動突き合わせ）。
- 実績（2026-06-11）:
  - **upstream 移植**（`cache-warden-authsock/src/upstream.rs`）: warden の `agent/upstream.rs` を移植。
    `Upstream::new(path)` / `connect()`（connect timeout 10s）/ `UpstreamConnection::send_receive()`
    （request timeout 30s、`AgentCodec` の write→read）。**warden 固有を削った点**: `from_env()`
    （`SSH_AUTH_SOCK` 起点の生成、cache-warden は config の `upstreams` 配列で明示指定するので不要）、
    `socket_path()` 以外の `stream_mut()` / `into_stream()`（warden の basic proxy 用、cache-warden は
    一発 send_receive のみで未使用）。エラー型は warden の巨大共通 Error から `Error::Upstream(String)`
    1 バリアントへ縮小（接続失敗で全体を壊さず該当 upstream のみスキップする graceful degradation の
    キャリア）。**防御維持**: upstream 応答も `AgentCodec` の size 上限 / framing / identity count 上限
    チェックを通る（upstream を信頼しない）。`tracing` は外し cache-warden 流。
  - **config 拡張**（`[authsock.sockets.NAME].upstreams`）: `~/` 展開付き path 配列、省略可。
    `keys` か `upstreams` のどちらかがあれば valid（upstream-only socket = 純フォワード を許可）。両方空は
    拒否。`deny_unknown_fields`。
  - **daemon 統合**（`cache-warden-cli/src/daemon/authsock.rs`）: `SocketState.upstreams: Vec<Upstream>`。
    接続ごとに `UpstreamRoutes`（blob→upstream index）を保持。
    - **REQUEST_IDENTITIES**: KV registry の identities を先に積み、各 upstream の identities を async で
      取得してマージ。`seen`（HashSet）で重複 blob を dedup（**KV 優先** = local が勝つ）。upstream が
      落ちていればスキップ + stderr 1 行警告（残りで応答）。non-IdentitiesAnswer 応答は「鍵なし」として
      寛容に扱う（warden 踏襲）。生き残った upstream blob を `routes` に記録。
    - **SIGN_REQUEST**: ① registry にあれば従来のローカル署名（`spawn_blocking` で認証ゲート経由、
      Iteration 1 経路）。② upstream 未設定なら FAILURE。③ `routes` に記録があればその upstream へ転送。
      ④ 記録が無い/stale なら全 upstream を順次試行（warden の fallback、列挙せず署名するクライアント用）。
      全滅で FAILURE。転送は `forward_sign`（接続失敗・非 SIGN_RESPONSE 応答は `None` で次へ）。
    - **async/blocking 分離**: upstream I/O は async（non-blocking socket）でランタイム上、KV ローカル署名
      （TouchID で分単位ブロックしうる）は従来通り `spawn_blocking`。
  - **接続都度（キャッシュなし）の理由**: warden 同様、upstream は REQUEST_IDENTITIES / SIGN_REQUEST
    ごとに `connect()`。1Password agent はロック/再起動で socket が揮発し、コネクションをキャッシュすると
    使用ごとに half-open 検出・復旧が要る。接続都度なら署名/TouchID レイテンシに対し無視できるコストで
    その複雑さを回避（`upstream.rs` の doc + DESIGN に明記）。
  - **macOS TCC 回避**（`cache-warden-cli/src/daemon/upstream_path.rs`）: upstream path が
    `Library/Group Containers/` 配下なら state dir（`$XDG_STATE_HOME/cache-warden/upstreams/`）に
    安定 symlink を張って経由（launchd 下で TCC ダイアログを避ける、warden の `onepassword_agent_socket`
    知見をそのまま取込）。Linux/その他は path をそのまま（cfg 分岐）。best-effort（symlink 失敗時は
    元 path で直接接続を試みる）。
  - **検証**: 単体（upstream 5 件: new / 接続失敗 = Upstream エラー / fake agent 応答 / closed = エラー、
    daemon 7 件: 未対応 type / merge / dedup local 優先 / upstream down 時 degradation / 列挙後の転送 /
    列挙なし fallback / local 鍵は upstream 併存でもローカル署名 / unknown blob FAILURE、upstream_path 2–3
    件: 非 Group-Container は verbatim / macOS symlink redirect）+ E2E（`authsock_e2e.rs` に 3 件追加:
    fake upstream agent を立て、`ssh-add -l` で KV+upstream 鍵がマージ列挙 / upstream 鍵への SIGN が転送
    されて upstream の sentinel 署名が返る / upstream 停止時に KV 鍵だけで列挙+ローカル署名 verify）。
    `just ci` 全通過、既存テスト回帰なし。
  - **brief から変えた点**: なし（milestone 通り）。新 DR 不要（KeySource 2 軸の agent proxy 経路の
    具体化で、DR-0004 判断 8 / 本 plan の範囲内。設計判断の追加なし）。

### Iteration 3: 鍵フィルタ ✅ 完了（2026-06-11）

- スコープ: `filter/*`（comment/fingerprint/keytype/pubkey/rule/evaluator、github/keyfile は後送り可）移植。
  socket 単位で REQUEST_IDENTITIES の公開鍵可視性を絞る。
- 依存: Iteration 1（identities 経路）。
- 検証: warden の filter テスト移植 + 実機で comment フィルタが効く（`ssh-add -L` の差分）。
- 実績（2026-06-11）:
  - **filter 移植**（`cache-warden-authsock/src/filter/`）: warden の `comment` / `fingerprint` /
    `keytype` / `pubkey` / `keyfile` matcher、`FilterRule`（`not-` 否定 + auto-detect）、
    `FilterEvaluator`（OR of AND）をそのまま移植。warden の各 matcher テストも移植して green。
    `pubkey` は wire blob を `key_data().encode()` で作り（registry / `Identity::new` と同じ符号化）、
    列挙 Identity と exact 一致することをテストで証明。`globset` / `regex` 依存を追加。
  - **github filter は未移植（後送り、port plan 許容範囲内）**: warden の `github=<user>` は
    `github.com/<user>.keys` を HTTP 取得し、重い HTTP クライアント依存（`reqwest` + TLS スタック）を
    呼ぶ。本 iteration の他フィルタは全てネットワーク不要・依存軽量なので、github だけ後段（op 発見
    iteration 以降 or hardening）に隔離した。`rule.rs` / `mod.rs` の doc に「deferred」と明記。
    ネットワーク不要の `keyfile`（ローカル authorized_keys）は移植済み（warden の `shellexpand` 依存は
    避け、`~/` のみの最小展開に置換。`tracing::warn!` は cache-warden 流 `eprintln!` に）。
    `evaluator` の `ensure_loaded`/`reload` は warden では github のため async だったが、github を外すと
    keyfile のみ（sync）になるので `reload` を sync 化した。
  - **config 拡張**（`[authsock.sockets.NAME].filters`）: warden の filter 文字列形式を踏襲しつつ新スキーマに
    馴染む形。warden の `deserialize_filters`（string = 単一ルール OR 項、配列 = AND グループ）を移植し、
    プロンプト例 `filters = ["comment=github*"]` がそのまま動く。`Vec<Vec<String>>`（OR of AND）。token の
    妥当性は config parse 時に `FilterEvaluator::parse` で検証（不正パターンは socket 名付きで fail-fast、
    `keyfile=` は実ファイル読込まで起動時に走る）。`deny_unknown_fields` 維持。
  - **daemon 統合**（`cache-warden-cli/src/daemon/authsock.rs`）: `SocketState.filter: FilterEvaluator`。
    - **REQUEST_IDENTITIES**: KV registry の comment 込み Identity と各 upstream の Identity をマージした
      後にフィルタ適用。通過鍵だけ列挙し、フィルタで隠れた upstream blob は `routes` にも記録しない
      （= 後続 SIGN で転送されない）。
    - **SIGN_REQUEST**: フィルタ通過鍵のみ署名許可。ローカル鍵は `handle_local_sign` 内で registry の
      comment 込み Identity を組んで判定（comment フィルタが直接署名経路でも効く）。upstream 鍵は列挙で
      記録した route 経由のみ（comment-only フィルタは「列挙してから署名」を要求 = warden 同様、列挙に
      出ない鍵への直接署名要求を拒否）。列挙なし fallback は blob だけの Identity で判定するので、
      `fingerprint` / `type` / `pubkey` は正確に許可/拒否、comment-only は deny。
    - フィルタ無し socket（`filters` 省略 = 空 evaluator）は従来通り全鍵。
  - **検証**: 単体（filter crate 全 matcher + evaluator テスト移植、config の filters パース 6 件、
    daemon ハンドラ 9 件: matching/excluding comment フィルタの local 署名、blob フィルタ type の許可/除外、
    列挙の絞り込み、隠れた upstream 鍵の非列挙・非ルーティング・SIGN FAILURE、comment 一致 upstream の
    列挙・転送）+ E2E（`authsock_e2e.rs` に 1 件追加: 2 socket 構成 = `filters=["comment=github*"]` の
    filtered socket と無フィルタの all socket、実 ssh-keygen 鍵 2 本で「filtered は github 鍵のみ列挙 /
    other 鍵への SIGN は FAILURE / filtered は github 鍵を署名 verify / all は両鍵列挙 + other 鍵署名
    verify」）。`just ci` 全通過、既存テスト回帰なし。
  - **brief から変えた点**: github filter を未移植（理由 = reqwest 等の重い依存。プロンプト・port plan
    とも後送り許容）。新 DR 不要（DR-0004「鍵フィルタ = アダプタ」の具体化、設計判断の追加なし）。
  - **互換メモ**: warden の SIGN 経路は `Identity::new(blob, "")`（comment 空）で `filter.matches` を直接
    評価し、allowed_keys_cache（列挙通過鍵）との OR で許可していた。cache-warden は allowed_keys_cache 相当を
    持たず、ローカルは registry の comment、upstream は `routes` を「列挙通過鍵の記録」として使う。意味論
    （列挙に出ない鍵への直接署名を拒否、blob 判定可能なフィルタは列挙なしでも評価）は warden と等価。

### Iteration 4: op 鍵発見 + ローカル署名（DR-011 / DR-015）✅ 完了（2026-06-11）

- スコープ: `keystore/op.rs` / `cache.rs` 移植 + 公開鍵レジストリ（key_blob → itemid）を実装。
  SIGN ミス時に `ValueSource::Command(op item get ...)` でコアに遅延 set → 署名（§1.3 案 / §1.4）。
  RSA PKCS#8 + SHA2 フラグ（DR-015）込み。
- 依存: Iteration 1（署名結線）+ Iteration 3（filter は op 鍵にも効く）。
- 検証: op:// source で `ssh-add -L` に op 鍵が出る、初回 SIGN で TouchID 1 回 → 2 回目以降キャッシュヒット
  （= soft TTL 内は再認証なし）。warden と TouchID 回数を突き合わせる。
- **最も重い iteration**。発見フローの TouchID 制御が壊れると日常利用が劣化するので慎重に。
- 実績（2026-06-11）:
  - **op CLI 抽象**（`cache-warden-authsock/src/op.rs`）: warden の `keystore/op.rs` を移植しつつ
    `OpClient` trait（`item_list_json` / `item_get_public_key_json`）で op CLI 呼び出しを境界化。
    本番は `RealOpClient`（同期 `std::process`、`op_account` を `--account` で渡す）、テストは fake op で
    JSON 解析・発見・キャッシュ・KV 配線を全網羅（実 op CLI 依存テストは CI に入れない）。`OpSource::parse`
    で `op://` / `op://VAULT` / `op://VAULT/ITEM` をパース、`validate_item_id`（英数字のみ）で itemid の
    flag injection を防止。`parse_item_list` / `parse_field_value` は純関数で単体テスト。
  - **ディスクキャッシュ**（`op_cache.rs`）: warden の `cache.rs` 移植。`$XDG_CACHE_HOME/cache-warden/op_map.json`
    （fingerprint → 公開鍵、秘密情報なし、0600）。path 注入可能（テストは temp dir）。version 不一致 /
    破損 / 不在は空キャッシュ（fail-open、ヒントに過ぎない）。
  - **発見ロジック**（`op_discovery.rs`）: DR-011 の **最小版（ディスクキャッシュ → op item list →
    op item get）**。source ごとに `op item list` 列挙 → fingerprint がキャッシュにあれば公開鍵再利用
    （op item get なし）、無ければ `op item get --fields public_key`。source 跨ぎは fingerprint で dedup。
    更新キャッシュを返す（daemon が保存）。`DiscoveredKey { item_id, public_key, title, fingerprint, vault }`。
  - **公開鍵レジストリ拡張**（`registry.rs`）: `RegisteredKey` に `KeySource`（`Local` / `Op { argv,
    soft_ttl_secs, hard_ttl_secs }`）を追加。`register_op_key` は**公開鍵 OpenSSH 文字列から** blob を導出
    （秘密鍵に触れない）。`Local` は従来 PEM 由来（Iteration 1）。
  - **コア KV 遅延配線**（`cache-warden-cli/src/daemon/authsock.rs`）: op 鍵は daemon 起動時に
    **レジストリにのみ登録**（コア entry はまだ無し = NotLoaded）。SIGN 時 `ensure_loaded` が分岐:
    - 既存 entry → Iteration 1 ゲート（Active=即署名 / SoftExpired=`extend_authenticated` / HardExpired=
      `regenerate` で同 argv 再実行）。
    - **op 鍵 + entry 不在** → `lazy_load_op_key`: runner で `op item get ... --reveal` 実行 → 再認証
      （fetch 先・auth 後の順は core regenerate と同じ。拒否時 value は zeroize drop）→ `store.set`
      （command source + source の TTL）。以降は soft 内キャッシュヒット、soft 切れ extend、hard 切れ
      regenerate。**warden では未配線だった TTL コアをここで初めて実配線**（port plan の肝）。
    - KV key は `__authsock_op:<item_id>` で namespaced（手動 `[kv.*]` と衝突回避）。
  - **op private_key の JSON 後処理問題（§1.4 / §3-11）の解決**: warden は `--format json` で取得し `.value`
    抽出していたが、cache-warden コアの `CommandRunner` は **stdout 生バイト**を値にするため JSON だと
    `{"value":"<PEM>"}` が保存されてしまう。→ `private_key_argv` は **`--format json` を付けず**
    `op item get ITEM --fields private_key --reveal`（プレーン PEM 出力）にした。コア既定の
    `TrailingNewline::TrimOne` が op の末尾改行 1 個を落とし、signer がパースできる PEM がそのまま残る。
    `--reveal` は concealed SSH key field 取得に必須（DR-011）。
  - **config 新スキーマ**（`[authsock.sources.NAME]` = `kind="op"` / `op_account` / `members` /
    `soft-ttl` / `hard-ttl`、`[authsock.sockets.NAME].source = "NAME"`）: `deny_unknown_fields`、
    起動時バリデーション（未対応 kind / 非 op:// member / 不正 TTL / 未宣言 source 参照を fail-fast、
    socket 名付き）。`members` 省略は `["op://"]`。`keys` / `upstreams` / `source` は併存可（1 socket が
    複数経路を束ねられる）。kawaz の実 warden 設定（`members=["op://"]` + `source="default"`）が動く。
  - **github フィルタ併用**: Iteration 3 で未実装のため、op source の socket が github フィルタを使う設定は
    config parse 時点で「未対応」として fail-fast（既存 github defer の扱いに合わせる。op 固有の追加対応なし）。
  - **検証**: 単体（op.rs 14 / op_cache.rs 7 / op_discovery.rs 6 / registry op 5 / daemon op-sign 8 +
    register 2 / config sources 13）+ E2E（`authsock_e2e.rs` に 2 件: **fake op スクリプトを PATH に置く**
    真の end-to-end。`op://` source で discovery → `ssh-add -l` に op 鍵列挙 → 初回 SIGN で遅延 fetch →
    署名 verify / `[auth].command=["false"]` で遅延 load の再認証拒否 → FAILURE + payload 空）。
    `just ci` 全通過（fmt / clippy -D warnings / test / build）、既存テスト回帰なし。
- **新規判断（要記録）**:
  1. **op 抽象の置き場**: アダプタ crate（`op.rs` / `op_cache.rs` / `op_discovery.rs`）。op CLI は
     `OpClient` trait 境界、本番 `RealOpClient`（同期 std::process）。理由 = SSH 鍵 ↔ 1Password の語彙は
     アダプタ責務（DR-0004）、trait 境界で CI に実 op を持ち込まずテスト可能。
  2. **op_source 設定 = `[authsock.sources.*]` + socket `source` 参照**（新スキーマ）。warden の
     `[[sources]] members` を cache-warden 流に翻訳。互換レイヤなし（§3 判断 2 確定方針どおり）。
  3. **NotLoaded = レジストリ + 遅延コア KV set**（§1.3 案 / §3 判断 4 確定どおり）。コアに「値なし entry」
     概念を足さず、アダプタ `KeySource::Op` が fetch 方法を保持、初回 SIGN で `store.set`。
  4. **private_key 取得はプレーン出力**（`--format json` なし、上記）。コア CommandRunner の生 stdout +
     TrimOne で PEM が綺麗に残る。アダプタ側の JSON 後処理は不要にした。
- **見送り（理由付き、Iteration 後送り or follow-up）**:
  - **DR-011 の 1Password agent socket 高速路（ステップ 3–4）**: 最小実装ではディスクキャッシュ +
    op item get のみ。理由 = agent socket 経由の fingerprint 照合は **二つ目の async 解決経路**を足す一方、
    定常状態（warm restart）はディスクキャッシュで op item get ゼロになり、初回発見時のみ 1 鍵 1 回
    op item get を払うだけ。本 iteration の本丸（前例のないコア KV / TTL 配線）に集中するため follow-up に
    隔離。`op_discovery.rs` の doc に明記。**未配線だが既存 `Upstream` クライアントで実装可能**。
  - **github フィルタ**: Iteration 3 同様未移植（HTTP 取得方式が別途決定待ち）。op source 併用は parse 時に
    未対応エラー。
  - **DR / journal 起票**: 上記新規判断は本 plan の Iteration 4 実績に集約。独立 DR は kawaz 判断
    （config 新スキーマ / op 抽象置き場は DR-0004 判断 2・8 の具体化の範囲内で、設計方針の新規追加なし）。

### Iteration 5: ポリシー（3 層）+ プロセス認証配線

- スコープ: `policy/engine.rs`（keys ∩ socket、most restrictive wins）移植。
  peer pid → `SystemInspector::ancestry`（コア）→ `allowed_processes` 照合（アダプタ）。
  cache-warden は peer.rs + ancestry を既に持つので結線するだけ。
- 依存: Iteration 1。
- 検証: allowed_processes に無いプロセスからの SIGN が拒否される（warden と突き合わせ）。

### Iteration 6: config（authsock 節）+ Phase 1 並走達成

- スコープ: cache-warden の TOML config に authsock 節（sources/sockets/keys）を追加（§3 論点）。
  `run` が config を読んで複数 authsock socket を起動。**別ソケットで warden と並走**（DR-0004 Phase 1）。
- 依存: Iteration 1–5。
- 検証: warden を従来通り動かしつつ cache-warden の authsock socket を別パスで起動、
  両方に同じ source を向けて挙動を突き合わせる（§4）。

### Iteration 7+（パリティ / 後期、Phase 2 以降）

- security（anti_debug 移植: §3 判断 5 の (a) core dump 抑制 / (b) ptrace 拒否 / (c) DYLD 検出を cli 側に）、
  refresh フロー（DR-007）、idle check（policy）、github/keyfile フィルタ、
  launchd/systemd サービス登録（cli 側 `daemon register|unregister` として、§3 判断 5 で確定）。
- これらは Phase 2（パリティ）に向けて積む。Phase 3（切替）・4（引退）は安定確認後。

---

## 3. 新規に必要な設計判断のリスト

### kawaz 判断が要るもの（方針・責務・破壊変更）

1. **アダプタの crate 分割**: `cache-warden-authsock` lib を新設するか、CLI 内モジュールにするか。
   推し = lib（重い ssh-key/rsa 依存をコアから隔離、DR-0002 維持）。要 DR 化。
   - **確定 (2026-06-11 kawaz)**: 3 crate 構成にする。`cache-warden`（コア lib）/
     `cache-warden-authsock`（アダプタ lib。ssh-key 等の重い依存をここに隔離）/
     `cache-warden-cli`（バイナリ。両 lib を結線）。プロセスは単一のまま（DR-0008 維持、
     アダプタはあくまで同一プロセス内 task として lib を呼ぶ）。
   - **接点規約**: アダプタは `SecretBytes` を所有せず短命借用のみ。`expose_secret()` が
     唯一の grep 可能な露出点で、コアの `Mutex` 下でのみ秘密値に触る。署名はアダプタが
     `expose_secret()` で借りてプロセス内で実施し、借用を即手放す。DR 化は実装 iteration で。
2. **config スキーマの authsock 節 + warden config 互換性**: cache-warden config は現状
   `[daemon]`/`[auth]`/`[kv.*]` のみ（`deny_unknown_fields`）。authsock 用に `[[sources]]`/`[sockets.*]`/`[[keys]]` を
   足す必要。**warden の config.toml をそのまま読めるようにするか**が判断点。
   - 互換にする利点: 切替時に設定移行不要、並走で同一設定を使え突き合わせが楽。
   - 互換にしない利点: cache-warden の設計（`[auth].command` は argv 配列 vs warden は string）に揃えられる。
     実際 warden `[auth].command` は文字列 1 個、cache-warden は `Vec<String>`。`[auth].method` も warden のみ。
   - **確定 (2026-06-11 kawaz)**: 新スキーマ（cache-warden 流）に寄せ、移行ガイドを書く。
     warden config は別物として並走。互換レイヤは持たない。DR 化は実装 iteration で。
3. **タイマー基準点（アイドルタイムアウト `last_used` touch を残すか捨てるか）**（§1.3 ギャップ 1）:
   **確定 (2026-06-11 kawaz)**: idle extend を採用する。アダプタが署名成功ごとに extend を呼び、
   Active 中は認証なしでリフレッシュする（頻用鍵は再認証なしで生き続け、放置すると soft 切れ）。
   - **重要な前提修正**: 現コアの `extend` は `activated_at` をリセットして hard まで動く曖昧仕様。
     これを **2 基準に分離**する: `loaded_at`（set/regenerate で固定、hard の基準）と
     `extended_at`（extend で動く、soft の基準）。extend は soft の基準（`extended_at`）だけを動かし、
     hard の基準（`loaded_at`）は触らない。
   - **明示の hard 延長 API**: `kv extend KEY --hard 8h` 相当の操作を追加（再認証付き）。
     夜間に hard 切れで AI 作業が止まるのを防ぐ用途。これは `loaded_at` 側を意図的に延ばす別経路。
   - この**コア修正（2 基準分離 + hard 延長 API）はアダプタ着手前の前提作業**として iteration 計画に
     追加する（§2 参照）。warden 実機がアイドルを使っているかの実機確認は引き続き iteration 1 着手前タスク。
4. **NotLoaded（公開鍵だけ先出し）のコア非対応をアダプタ吸収で許容するか**（§1.3 ギャップ 3）:
   コアに「値なし公開鍵エントリ」概念を足さず、アダプタの公開鍵レジストリで吸収する案を推す。
   コアを汚さない方針の確認。
   - **確定 (2026-06-11 kawaz)**: アダプタ側の公開鍵レジストリで吸収する。`ssh-add -l` 相当の
     列挙はそのレジストリから返す。コアには「値なしエントリ」概念を足さない（コアは値を持つ KV に徹する）。
5. **anti-debug / サービス登録の所属**: DR-0004 は anti-debug を「コア」と書くが cache-warden コアに無い。
   プロセス全体保護なので daemon(CLI) 起動時が素直。サービス登録も DR-0004 で「コア側見込み・未確定」。要判断。
   - **整理確定 (2026-06-11 kawaz)**: anti-debug を 3 段に分解する。
     - **(a) core dump 抑制**（`PR_SET_DUMPABLE=0` / `RLIMIT_CORE=0`）: 事故防止価値が高く、早期に必ず入れる。
     - **(b) ptrace 拒否**（`PT_DENY_ATTACH`）: opt-out 可能な形で hardening iteration に入れる。
     - **(c) DYLD 検出**: 優先度低（後期 or 見送り検討）。
   - 実装の所属は**デーモン起動時（cli 側）**。プロセス全体の保護なのでアダプタではなく cli が素直。
   - **サービス登録**は `daemon register` / `daemon unregister` サブコマンド（CLI 再構成で新設した
     `daemon` グループ配下）として cli 側に置く。
6. **op 署名フックをコア trait にしない**（§1.5）: コアは「値を返す KV」まで、署名はアダプタ。
   この責務線を確定（design-priority / design-thinking ルールに沿う）。
7. **privilege separation（OpenSSH 流）を将来オプションとして検討**:
   秘密値を持たない側（SSH agent protocol のパーサ）を sandbox 子プロセスに分離し、
   構造化済みの要求だけを親プロセスに渡す。秘密値は親から出ないので DR-0008（秘密値の 1 プロセス
   閉じ込め）と両立する。hardening フェーズの将来検討事項として記録。
8. **KeySource 抽象の 2 軸**: アダプタの鍵ソース切替点として最初から 2 経路を設計に織り込む。
   - **(1) agent proxy 経路**: `SSH_AUTH_SOCK` を持つ別マネージャに対し、列挙も署名も agent protocol で
     転送する。秘密鍵素材は取れず、署名要求を上流 agent に転送して結果を返すだけ。
   - **(2) CLI 取得 + ローカル署名経路**: `op read` 相当のベンダ CLI で鍵素材を取得し、プロセス内で署名する
     （コア `Store` + `ValueSource::Command` + アダプタ signer）。
   op 以外（KeePassXC / Bitwarden 等）の具体ソース調査は将来（要調査）。抽象だけ先に切っておく。

### 実装判断で済むもの（手を動かす中で決まる）

9. **SSH agent protocol crate を使うか warden 自前 codec を移植するか**: 移植を推す。
   - 根拠: warden の codec は MAX_BLOB_SIZE / MAX_IDENTITIES 上限・truncated/oversized 検査・
     RSA SHA2 フラグ込みで完成度が高く、テストも揃う。外部 ssh-agent crate に乗り換えると
     仕様差（フラグ扱い・エラー境界）の再検証コストが移植コストを上回る。`ssh-key`（鍵パース）は
     既に warden が使っており継続。
10. **コア `Store` のキー型**（§1.3 末尾）: SSH key_blob（バイナリ）をコアキーにするため、
    base64 等で String 化する（コアは `String` キー）。コアキー型の変更は避ける（影響大、設計を歪めない）。
11. **op private_key 取得の JSON 後処理**（§1.4）: `ValueSource::Command` に op をそのまま渡すと
    JSON が返る。`--reveal` でプレーン取得 or アダプタで `.value` 抽出。`CommandRunner` の改行トリムとの相性確認。
12. **依存追加**: アダプタ crate に `ssh-key` / `bytes` / `ed25519-dalek` / `rsa` / `pkcs8` /
    `sha1` / `sha2` / `signature` / `base64` を追加。`tracing`（warden が多用）を入れるか、
    cache-warden の eprintln スタイル（server.rs は tracing 不使用）に合わせるか。**推し = tracing 不採用、
    cache-warden 流の最小ログに寄せる**（依存最小・既存スタイル一貫）。tokio は CLI 側で既存。
13. **`AllowAll` の扱い**: cache-warden は `[auth].command` 未設定で `AllowAll`（再認証なし）。
    authsock socket でも soft 切れ時に再認証コマンドを使う。warden の `[auth].command`(string) を
    cache-warden の `CommandAuthenticator`(argv) にマップ。env で渡す情報（KEY/OPERATION/REQUESTER）の
    SSH 文脈での意味づけ（KEY = 鍵 comment/fingerprint?）を決める。

---

## 4. リスクと検証戦略

### 4.1 並走検証（warden と挙動突き合わせ）

DR-0004 Phase 1–2 の「別ソケットで並走 → 挙動比較」を具体化する。

- **二重 socket セットアップ**: warden を従来パス（例 `$XDG_RUNTIME_DIR/authsock-warden/work.sock`）で
  日常稼働させたまま、cache-warden authsock socket を別パス（例 `.../cache-warden/work.sock`）に起動。
  同一 source（op:// / agent / file）を両者に向ける。
- **REQUEST_IDENTITIES 突き合わせ**: 両 socket に `SSH_AUTH_SOCK=<path> ssh-add -L` を打ち、
  返る公開鍵集合（フィルタ後）が**バイト一致**することを確認。差分はフィルタ/発見ロジックの移植バグ。
- **SIGN 突き合わせ**: 同じ challenge を両 socket で署名させ、検証鍵で両方 verify が通ることを確認。
  Ed25519 は決定的なので署名バイト一致も確認可能（RSA SHA2 は決定的、ssh-rsa SHA1 も）。
- **TouchID 回数突き合わせ**（最重要 UX 指標）: op 発見 + 初回 SIGN で TouchID 1 回、
  soft TTL 内の連続署名で 0 回、soft 切れで再認証 1 回、を warden の挙動と比較。回数が増えていたら
  キャッシュ/TTL 配線のバグ（§1.3 / §1.4）。
- **観測道具**（empirical-verification ルール）: `ssh-add -L` / `ssh -v` / 署名 verify スクリプト /
  audit ログ（warden は `authsock_warden::audit` ターゲットに JSON 出力、cache-warden 側も同等の
  構造化ログを足して diff る）。プロセス認証は `lsof`/`ps` で peer pid を実確認。

### 4.2 kawaz の日常鍵利用を壊さない手順

DR-0004 不変条件「全フェーズで SSH 署名 / 1Password 連携を中断させない」を守る。

- **切替まで `SSH_AUTH_SOCK` を変えない**: Iteration 1–6 の間、kawaz の実 `SSH_AUTH_SOCK` は
  warden（または 1Password agent）のまま。cache-warden の authsock socket は**別パス**でだけ起動し、
  手動で `SSH_AUTH_SOCK=<cache-warden path>` を指定したときだけ使う（検証用）。
- **Phase 3（切替）は可逆に**: `SSH_AUTH_SOCK` を cache-warden 側に向ける変更は、`~/.ssh/config` や
  shell env の 1 行差し戻しで即元に戻せる形にする。問題が出たら warden へ即フォールバック（DR-0004）。
- **op item get の TouchID を壊さない**: コア `CommandRunner` は timeout=無制限がデフォルト（TouchID 待ちを
  殺さない設計、source.rs doc 明記）。op 取得経路で timeout を設定しない。
- **mlock fail-open**: コア `SecretBytes` の mlock は fail-open（権限なしでも動く）。launchd 起動時に
  mlock 上限に当たっても署名は止まらない（`is_locked` で観測のみ）。日常利用は劣化しない。
- **二重起動ガード**: cache-warden の control socket は connect 試験で二重起動を `AddrInUse` 検出済み。
  authsock socket 群にも同じ stale 検出 + umask 0600 を適用し、warden の socket を誤って奪わない
  （別パスなので衝突しないが、bind 前の存在チェックを徹底）。

### 4.3 移植固有リスク

- **registry 未配線疑惑（§1.3）の解消が前提**: 4 状態が warden 実機でどう動くか未確認のまま
  コアにマップすると、存在しない挙動を再現しようとして空回りする。**Iteration 1 着手前に
  warden の `run` 経路（cli/commands/run.rs と registry の結線）を読み、実機で lock/forget が
  発火するか観測する**（empirical-verification）。本ドラフトでは未読のため不明と明記。
- **秘密鍵が IPC を渡らない不変条件（DR-0008）**: アダプタを同一プロセス内 task にすることで、
  PEM / `SecretBytes` がプロセス境界を越えない。署名はアダプタが `expose_secret()` で借りて
  プロセス内で実施。子プロセス化（op CLI）は値の**取得**のみで、取得後は in-process。維持を確認。
- **op JSON 後処理（§3-9）の取りこぼし**: 値に余計な JSON/改行が混ざると署名鍵パースが失敗する。
  Iteration 4 で PEM パース（signer の pem_kind 判定）が通ることを実鍵で確認。

---

## 5. 結論サマリ（kawaz レビュー用）

- **移植マッピングの結論**: コア（TTL/メモリ保護/プロセス認証/再認証）は cache-warden に実装済みなので
  **作り直さず流用**。warden からは **アダプタ部分のみ移植**（SSH codec / upstream / filter / signer / op 発見 /
  policy）。warden の `KeyRegistry`(4 状態)・`SecretKeyData`・`KeyTimer`・`security::memory` は
  **コアの `CacheEntry`/`Ttl`/`SecretBytes` に置換**。4 状態は `Active=Active` / `Locked=SoftExpired(再認証で復帰)` /
  `Forgotten=HardExpired(command 型は regenerate)` / `NotLoaded=アダプタの公開鍵レジストリ` で表現。
  op 発見（DR-011）はアダプタ、秘密鍵の遅延取得・キャッシュ・TTL はコア `Store` + `ValueSource::Command`、
  1Password 署名（signer）はアダプタ（`SecretBytes` を借りて署名）。
- **iteration 分割案**: 0 codec → **1 最小 milestone（socket 1 本 + static 鍵で署名、妥当と判断）** →
  2 upstream → 3 filter → 4 op 発見+署名（最重） → 5 policy → 6 config + Phase 1 並走達成 → 7+ パリティ。
- **kawaz 判断（2026-06-11 確定）**: (1) 3 crate 構成（コア lib / authsock アダプタ lib / cli バイナリ、
  プロセスは単一）、(2) config は新スキーマ（warden 互換レイヤ無し、移行ガイドで対応）、
  (3) タイマーは idle extend 採用 + コアを `loaded_at`(hard 基準)/`extended_at`(soft 基準) の 2 基準に分離
  + `kv extend --hard` 明示延長 API をアダプタ前のコア修正として追加、(4) NotLoaded はアダプタの公開鍵
  レジストリで吸収（コアに値なしエントリ概念を足さない）、(5) anti-debug は (a) core dump 抑制を早期必須 /
  (b) ptrace 拒否を opt-out 可能な hardening / (c) DYLD 検出は低優先、サービス登録は `daemon register|unregister`
  として cli 側、(6) 署名フックはコア trait にしない（署名はアダプタ）。
  - **将来検討**: (7) privilege separation（秘密値を持たないパーサを sandbox 子プロセスに分離、DR-0008 と両立）、
    (8) KeySource 2 軸（agent proxy 転送 / CLI 取得 + ローカル署名）を抽象として先に設計に織り込む
    （op 以外のベンダ CLI 調査は将来）。
- **要・実機確認（不明点）**: warden の `KeyRegistry`(4 状態)・`KeyTimer`(アイドル) が `run` 経路で
  実配線・発火しているか。warden_proxy は registry を経由せず独自 `cached_pem` を使っており、
  4 状態が実機で動いていない可能性がある。Iteration 1 着手前に warden の run 経路を読んで確定すること。
