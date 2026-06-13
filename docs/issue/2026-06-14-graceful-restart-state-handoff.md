# graceful restart: kv + endpoint fd を引き継いで新バイナリへ（アイデア記録）

- status: idea
- 記録: 2026-06-14（kawaz との議論メモ。未着手・未決）
- 関連: DR-0021（signal/shutdown。本件はその「理想形 restart」）/ `justfile on-success-release` の daemon 再起動案内（= 非 graceful 経路の現状）/ [2026-06-14-ssh-agent-provider-architecture](./2026-06-14-ssh-agent-provider-architecture.md)（kv に秘密集約・公開鍵 index の構造と直結）

## 動機

**そもそも kv を維持したい根本理由 = op の TouchID サイクルに引き戻されたくない**。
cache-warden の存在意義は「大抵のシークレット（ssh 鍵に限らず TOTP 等も）は op の中にあるが、
op の TouchID サイクルは硬直的で、**頻度の高低・果てはリモート承認可否をアイテム毎に制御できない**。
キャッシュ側で per-item に auth サイクルを制御する自由を得る」こと。**再 fetch = op サイクルへの
逆戻り = この価値を捨てる行為**。

`brew upgrade` 後の通常再起動は in-memory cache（秘密値・TTL・pin・auth 状態）を全消し → 全エントリが
op TouchID サイクルに引き戻される（storm）。理想は **kv（cached secret + その TTL/pin/auth 状態）と
endpoint fd（socket 群）を引き継いだまま新バイナリへ graceful 切替、旧プロセスは死ぬ**
（nginx graceful upgrade / systemd socket activation の系譜）。これで無停止 + **op サイクルへの
逆戻りなし**。ssh に限らず cache-warden が抱える全シークレット種別に効く。

## 2 層に分解

### 1. endpoint fd の継承（= 枯れた領域、難しくない）
control socket + `[authsock.sockets.*]` の listening fd を新プロセスへ:
- `SCM_RIGHTS` で fd 送信、または CLOEXEC を外して `exec` 継承。
- nginx / systemd socket activation と同じ手法。接続中クライアントの扱い（drain or 引き継ぎ）は別途。

### 2. kv（秘密）の継承（= セキュリティの肝、ここが主論点）
`execve` はアドレス空間を丸ごと置換し mlock メモリを持ち越せない。**=旧プロセスが秘密を保持したまま、別アドレス空間の新プロセスへ転送するしかない**（nginx 的に旧が新を起こして渡す）。

**合意した secure handoff 設計（2026-06-14 kawaz と確認、許容内）**:
1. **旧プロセス主導**: 稼働中の旧 daemon が新バイナリを自分で fork+exec し、秘密は継承 fd でのみ渡す。「新が control socket に来て要求」型は要求元認証が要りソケットに触れる誰もが試せるので却下。
2. **匿名 socketpair（fd 継承）**: `socketpair(AF_UNIX)` の片端を子に継承 fd で渡す。パス名を持たない＝第三者 connect 不能で **チャネルが構造的に private**（傍受・なりすまし接続を同時に排除）。ディスク非経由（カーネル内）。endpoint listening fd も同経路/SCM_RIGHTS で継承。
3. **後継バイナリ検証**: 渡す前に exec 対象を検証（macOS codesign(DR-0020)/最低 owner・期待パス・非 world-writable）。**TOCTOU 対策**: open した fd を検証 → 同 fd を `fexecve`（検証実体＝実行実体を一致）。macOS はカーネルが exec 時 codesign 再強制。残リスクは bounded で許容。
4. **メモリ衛生**: 転送バッファ両端 mlock、新側は受領後即 SecretBytes(mlock)化、旧側は成功後 zeroize→exit。平文窓最小化。
5. **二相コミット（fail-safe）**: 新が「全秘密+auth/TTL/pin 状態 受領・mlock・serve 開始」を通知 → 確認後だけ旧が fd 手放し zeroize+exit。失敗したら旧は稼働継続（cache 喪失なし=op サイクル逆戻りなし、最悪現状維持）。新旧とも serve しない窓を作らない。

**残リスク（許容）**: 同一 uid 攻撃者は元々メモリ読取りの可能性（PT_DENY_ATTACH(DR-0007)で緩和、万能でない）。handoff の新規露出は「転送中の一瞬の平文」のみで mlock+カーネル内+即 zeroize で最小化、同 uid が既に持つ権限を超えない。Linux は署名検証が弱く owner/perms/hash pin で代替。新バイナリは旧の全秘密を継ぐ＝署名済み upgrade を信頼するなら後継も信頼、の整理。

**信頼境界の判断**: 「バイナリが変わったら re-auth で信頼を張り直す」のが本来安全側。**この trust を受け入れないなら graceful でなく非 graceful restart（cache クリア）を使う** = graceful は opt-in、非 graceful restart が保守的デフォルト（下記スコープ）。

## provider/kv 構造との整合（2026-06-14 provider 記録を踏まえ）

provider 再設計で「秘密は core kv・公開鍵は adapter index」に集約する方針なので、graceful restart は:
- **KeySource / Keyring（= kv-backed）**: core kv の cached secret + その TTL/pin/auth 状態を handoff（案 a/b）。
  **source 種別（op:// か static か）に関わらず handoff が必要**。op:// 由来でも「再 fetch すれば良い」は誤り
  — 再 fetch は op TouchID サイクルへの逆戻りで、キャッシュの存在意義そのものを壊す（上記「動機」）。
  static(ssh-add) 由来はそもそも再 fetch 不可。**どちらも handoff 一択**。
- **公開鍵 index**: 非秘密なので handoff も再構築も安い（ここだけは再構築で代替可）。
- **UpstreamAgent**: 秘密も cache も持たない純 proxy なので handoff 不要、新プロセスで upstream へ再接続するだけ
  （= cache を持たない＝そもそも守るべき状態が無い、という例外）。
- → **handoff 対象は kv-backed Provider の cached secret 全部**（auth サイクル状態込み）。source 種別で絞れる
  という当初の観察は誤り。絞れるのは「cache を持たない UpstreamAgent は対象外」という点のみ。

## 詰めどころ（secure handoff 設計は §2 で確定、残り）

- 接続中クライアントの drain / 引き継ぎ。
- handoff 対象 = kv-backed Provider の cached secret 全部 + auth/TTL/pin 状態（op://・static 問わず）。UpstreamAgent のみ cache 無しで対象外。
- 直列化フォーマット（secret + メタ状態のワイヤ形式、両端 mlock）。
- 二相コミットの通知プロトコル（socketpair 上の ready/commit メッセージ）。

## 方針 / スコープ

- **graceful restart は opt-in**。trust（後継が旧の全秘密を継ぐ）を受け入れない場合は **非 graceful restart（cache クリア = op サイクル逆戻り）が保守的デフォルト**として常に在る。「信頼しないなら graceful でなく restart を使え」。
- DR-0021（shutdown 確定）の次段。実装難度・セキュリティレビュー量が大きく、本記録は idea 段階。実装着手前に DR 化（handoff 設計は §2 で大枠合意済み、残るは上記詰めどころ）。当面は justfile の「手動再起動案内（cache クリア前提）」で運用。
