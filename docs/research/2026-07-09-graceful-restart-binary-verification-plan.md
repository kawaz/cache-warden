# cache-warden: graceful restart + バイナリ真正性検証 設計プラン

対象: 開発セッション向け実装計画
最終更新: 2026-07-09

---

## 0. これは何か

cache-warden（in-memory KV / secret store）に、**core storage のデータを損なわずにバイナリを更新する graceful restart** を追加する。方式は `exec + fd 渡し`：現行プロセスが core storage をシリアライズし、fd 経由で新バイナリプロセスへ渡して restore する。

その際、新バイナリ（restore 先）は **「自身と同一パスかつ同一署名のバイナリ」でのみ機能させたい**。macOS では codesign（Team ID / Designated Requirement）で実現できるが、Linux には mac の `SecCode` / `csops` に相当する「実行中コードの署名を OS に問い合わせる統一 API が存在しない」。よって **何をもって同一署名とみなすかを自分で定義し、自前検証する**のが本設計の骨子。

---

## 1. 脅威モデル（先に境界を引く）

**守る相手（in scope）**
- 非特権・同一 UID の攻撃者が、restore 先バイナリを別物に差し替える
- PATH / ファイル差し替えで restart 先を乗っ取る
- 検証と exec の隙間を突く TOCTOU

**守らない相手（out of scope、明示的に諦める）**
- ローカル root / カーネルを騙せる攻撃者。root は memory を直接読め、埋め込み公開鍵ごとバイナリを差し替えられる。ここまで守るならカーネル機構（fs-verity 強制検証 / IMA appraisal + Secure Boot）が必須で、それは配布モデル（後述）を崩す。本設計の L1 は **非特権攻撃者に対して mac の Team ID 検証と等価な保証**を与えるもの、と割り切る。

**「同一署名」の定義（最重要）**
graceful restart の目的はバイナリ**更新**なので、新バイナリはハッシュが変わる。したがって狙うのは「同一ハッシュ」ではなく **「同じ署名鍵で署名された正規ビルドか」**。これは mac の Team ID / Designated Requirement 一致に対応する。

```
「同一ハッシュ」= 全く同じビルド        → バージョンアップと両立しない  ✗
「同一署名鍵」  = 同じ鍵で署名された正規ビルド → graceful restart に適する  ✓
```

---

## 2. アーキテクチャ全体（2 層 + 疎結合）

```
L1（コア・常時有効・単一バイナリ配布に完全に乗る）
   末尾追記署名 + 埋め込み公開鍵 + fexecve
   = identity（正規ビルドか）の検証。restart 時に必須。

L2（オプトイン・対応環境のみ・rpm/deb/apk の setup に乗せる）
   fs-verity（モードB = アプリ自前照合）
   = ファイル完全性の追加保証。非対応環境では静かに縮退。

疎結合の接続点:
   L1 署名鍵で署名した manifest に fs-verity 期待 digest を記載し、
   restart 時に measure した実 digest と照合する（循環回避のため digest は
   末尾ブロブではなく manifest 側に置く。§5 参照）。
```

配布モデル（アーキごとの single binary を gh release）に**きれいに乗るのは L1 のみ**。L2 は「配布物に焼くもの」ではなく「設置後にファイルシステム上で有効化するもの」なので、パッケージの post-install に乗せる。

---

## 3. L1: 末尾追記署名フォーマット

カーネルモジュール署名と同じ「末尾追記」方式。ELF セクション埋め込みは「そのセクションを署名計算から除外する正規化」が必要（＝ mac cdhash と同じ手間）なので採らない。末尾追記なら正規化が最小。

```
[   ELF binary body   ][  SigTrailer  ]
 \___ 署名対象の一部 __/
```

### SigTrailer レイアウト（末尾から遡れる構造）

```
offset(末尾から)  field         size   説明
----------------------------------------------------------------
                  magic_begin   8      "CWSIG\0\0\1"（ブロブ先頭マーカ）
                  format_ver    u16    フォーマットバージョン
                  sig_alg       u16    1 = ed25519
                  key_id        8      公開鍵 fingerprint 先頭 8B（鍵ローテ対応）
                  payload_len   u32
                  payload       可変   canonical CBOR（下記）
                  signature     64     ed25519(body ‖ payload)
                  trailer_len   u32    SigTrailer 全体長（末尾から遡るため）
末尾             magic_end     8      "CWSIGEND"
```

### payload（CBOR, canonical）
```
{
  "v":        version 文字列 (例 "1.4.2"),
  "vcode":    u64  monotonic version code（downgrade 防止用, §7）,
  "arch":     "x86_64" | "aarch64" | ...,
  "built":    RFC3339 UTC build time,
  "body_sha": body 部分の SHA-256（循環しない。fs-verity digest はここに入れない）
}
```

### 署名対象と検証手順
- 署名対象 = `body ‖ payload`（`signature` 自身・`trailer_len`・`magic_end` は対象外）。
- `body_sha` は body（＝ trailer より手前）だけを対象にするので**循環しない**。
- **fs-verity digest はここに入れない**（ファイル全体依存で循環するため。§5）。

検証（疑似コード）:
```c
// fd は検証対象バイナリ（O_RDONLY で開いた本物の fd）
read_tail(fd, &tr);
assert(memcmp(tr.magic_end, "CWSIGEND", 8) == 0);
locate_blob_from(tr.trailer_len);              // 末尾から遡ってブロブ先頭へ
assert(memcmp(tr.magic_begin, "CWSIG\0\0\1", 8) == 0);
assert(key_id_is_trusted(tr.key_id));          // 埋め込み公開鍵集合(current+previous)と照合
ok = ed25519_verify(pubkey[tr.key_id], body ‖ payload, tr.signature);
assert(ok);
assert(sha256(body) == payload.body_sha);      // 念のため自己整合
// downgrade 防止（§7）: payload.vcode >= self.vcode
```

---

## 4. graceful restart 手順（TOCTOU と secret 取り扱い）

### 4.1 TOCTOU を避ける：検証したまさにその fd を exec する
「パスを検証 → そのパスを execve」は検証と exec の隙間で差し替え可能（TOCTOU）。**検証した fd をそのまま exec** する。

```c
// 1. /proc/self/exe を readlink して同一パスを解決 → その"パス"は持ち回らず、fd を先に開く
int fd = open(new_binary_path, O_RDONLY | O_CLOEXEC);

// 2. fstat で inode / 所有者 / パーミッションを確認
//    - 他人書き込み可(w for group/other)でないこと
//    - 想定 uid 所有であること
fstat(fd, &st);
assert(!(st.st_mode & (S_IWGRP | S_IWOTH)));

// 3. その fd の中身を検証（§3 L1 検証）
verify_L1(fd);                 // NG なら restart 中止（元プロセス継続）

// 4. （対応環境のみ）L2 照合（§5）
verify_L2_if_available(fd);

// 5. 検証した"その fd"を直接 exec（パス経由で開き直さない）
fexecve(fd, argv, envp);       // or execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

`fexecve` / `execveat(AT_EMPTY_PATH)` により、**検証したバイトと実行されるバイトの同一性を OS レベルで保証**する。「同一パス」要件は §4.1 手順2 の readlink 解決で担保しつつ、実体は fd で固定する。

### 4.2 core storage を渡す fd
- `memfd_create` + `fcntl` seals（`F_SEAL_WRITE` 等）で内容の再マップ・改変を封じる。
- 渡す直前だけ平文化 → fd に書く → **元バッファは即 Zeroize**。
- 新プロセスは起動直後に fd から読み、read 済みバッファを即 Zeroize、fd を close。

### 4.3 ptrace / coredump 窓を開けない
- 親子とも `PR_SET_DUMPABLE = 0`、YAMA `ptrace_scope` を restart 前後で維持。
- **exec で `PR_SET_DUMPABLE` はリセットされる**ので、新プロセス側で **restore 前に再設定**する（ここが抜けると restart の一瞬だけ ptrace/coredump 窓が開く）。
- 既存の Zeroizing / ptrace 耐性ポリシと一貫させる（secret は get/set の一瞬以外 Zeroize、の原則を restart 経路でも守る）。

---

## 5. L2: fs-verity（モードB = アプリ自前照合）と循環参照の回避

### 5.1 なぜ fs-verity は単一バイナリ配布に「そのまま」乗らないか
fs-verity は**ファイルシステムの機能**であり、署名や Merkle tree はバイナリ内部ではなく設置先 FS のメタデータに保持される。配布した時点では何も効かず、**設置先で対象ファイルを有効化して初めて意味を持つ**。よって配布物には焼けず、post-install（deploy 手順）側の話になる。

環境要件（縮退前提）:
- ext4 / f2fs / btrfs かつ verity 有効マウントが必要。tmpfs / NFS / 多くの overlayfs では不可。
- **コンテナ（overlayfs）と相性が悪い**（single binary はコンテナで動かされがち）。
- 有効化は特権操作（要 root）。カーネル config 依存（built-in signature 強制なら keyring 設定も）。

### 5.2 2 モードのうち B を採用
- **モードA（カーネル強制）**: `.fs-verity` keyring に公開鍵登録 + `fs.verity.require_signatures=1`。open/exec 時にカーネルが弾く。最強だが keyring 設定という別 setup が付き、パッケージだけで完結しない。
- **モードB（アプリ自前照合・採用）**: enable は digest 生成のためだけに使う。restart 時に cache-warden 自身が `FS_IOC_MEASURE_VERITY` で digest を取り、**L1 鍵で署名済みの manifest 記載の期待 digest と照合**。keyring 不要で single binary 配布と一貫。

### 5.3 循環参照の回避（fs-verity digest は manifest へ）
fs-verity digest は**ファイル全体（末尾署名ブロブ込み）**から計算される。末尾ブロブに digest を入れると「digest 計算に署名が要る／署名に digest が要る」で循環する。よって:

- **末尾署名ブロブ**: 本体に閉じる値のみ（`body_sha`, version 等）。
- **fs-verity 期待 digest**: ファイル確定後にビルドで計算し、別立ての `manifest.json` に記載、**同じ L1 鍵で署名**して配布物に同梱。

```
manifest.json（配布物・パッケージに同梱）
{
  "name": "cache-warden",
  "version": "1.4.2",
  "vcode": 10402,
  "artifacts": [
    {"arch":"x86_64",  "file":"cache-warden-1.4.2-x86_64",  "sha256":"...", "fsverity_sha256":"..."},
    {"arch":"aarch64", "file":"cache-warden-1.4.2-aarch64", "sha256":"...", "fsverity_sha256":"..."}
  ]
}
manifest.json.sig   ← ed25519(manifest.json)  同じ鍵
```

restart 時の L2 照合:
```c
if (fsverity_available(fd)) {
    measure_verity(fd, &digest);                 // FS_IOC_MEASURE_VERITY
    m = load_signed_manifest();                  // manifest.json + .sig を L1 鍵で検証
    assert(digest == m.artifact[arch].fsverity_sha256);
} // 非対応環境: L1 のみで続行（graceful degradation）
```

---

## 6. 配布とパッケージング

### 6.1 gh release で rpm/deb/apk
- ホスティングとしては問題なし。ただし**野良配布**（ディストリのリポジトリメタデータを持たない）。
  - `apt/dnf/apk install` の自動更新経路には乗らない。ユーザーは asset を落として `dpkg -i` / `dnf install ./x.rpm` / `apk add ./x.apk --allow-untrusted`。
- パッケージ署名の文化差:
  - **rpm**: パッケージ自体に GPG 署名可（`rpm --addsign` / `rpm -K`）。野良でも有効。
  - **deb**: 単体署名(debsig)は不普及。通常リポジトリ Release 署名で担保 → 野良では効かない。detached sig を別添。
  - **apk(Alpine)**: 署名必須文化（abuild-sign + `/etc/apk/keys`）。野良は `--allow-untrusted`。musl/BusyBox で `fsverity` ツールが無いこと多い → L2 縮退。
- 実務: `SHA256SUMS` + **minisign / cosign(sigstore)** を asset に添える。
- ただし **L1 署名が実質 the root of trust**。パッケージ署名は補助。残課題は初期信頼（TOFU, §8）。

### 6.2 post-install に L2 を乗せる（例: debian postinst）
```sh
BIN=/opt/cache-warden/bin/cache-warden
if command -v fsverity >/dev/null && \
   fsverity enable "$BIN" --signature=/usr/share/cache-warden/cache-warden.sig 2>/dev/null; then
    echo "fs-verity enabled"
else
    echo "fs-verity unavailable; running with L1 signature only"   # install は成功させる
fi
```
- **enable 失敗でも install は成功**（graceful degradation）。overlayfs/tmpfs では失敗するのが正常。

### 6.3 upgrade での落とし穴
- fs-verity 有効ファイルは**内容変更不可（write/truncate 不可）だが unlink/rename は可能** → dpkg/rpm の「消して置き直す」upgrade は通る。
- ただし**置き直した新ファイルは verity 無効に戻る** → **毎回の upgrade で post-install が enable し直す**必要。graceful restart でバイナリ更新した直後の新ファイルも同様（更新パスに enable を通すか、次回 install 契機で有効化）。

---

## 7. downgrade 防止

古い脆弱バージョンへの restart を拒否する。`payload.vcode`（monotonic version code）を使い、restart 時に `new.vcode >= self.vcode` を要求。ポリシは要検討（同一 vcode の再起動は許可、より小さい vcode は拒否 or 明示フラグでのみ許可）。manifest 側 `vcode` とも整合を取る。

---

## 8. 鍵管理と初期信頼

- **検証鍵（公開鍵）はバイナリに埋め込む**。`key_id`（fingerprint 先頭 8B）で識別。
- **鍵ローテ対応**: 埋め込みは current + previous の複数を許容し、`key_id` で選択。移行期間中は旧鍵署名も受理。
- **署名鍵（秘密鍵）**: リリース CI の署名専用環境に隔離（HSM / OIDC keyless(cosign) も検討）。開発機に置かない。
- **初期信頼 (TOFU)**: gh release で最初に入手するバイナリの埋め込み鍵をどう信頼するか。TLS + `SHA256SUMS` + minisign/cosign で入手経路を固め、以降は埋め込み鍵チェーンで自己完結。ドキュメントに公開鍵 fingerprint を明記。

---

## 9. mac ↔ Linux 対応表

| 目的 | macOS | Linux（本設計） |
|---|---|---|
| 同一 identity 判定 | Team ID / Designated Requirement | 自前 ed25519 署名鍵の一致（L1）|
| コード完全性の OS 保証 | SecCode / cdhash | fs-verity 署名（L2）/ IMA appraisal（範囲外）|
| 検証バイトの exec 保証 | SecCode が担保 | `fexecve` / `execveat(AT_EMPTY_PATH)` |
| digest 正規化 | cdhash（署名部を除外して再ハッシュ） | 末尾ブロブは body のみ対象。fs-verity digest は manifest 経由で循環回避 |

---

## 10. 実装チェックリスト（フェーズ分け）

**Phase 1: L1 コア（配布に必須）**
- [ ] SigTrailer フォーマット確定（magic / CBOR payload / ed25519）
- [ ] ビルド後署名ツール（body への ed25519 署名 → 末尾追記）
- [ ] 検証ルーチン（末尾から遡り → key_id 照合 → 署名検証 → body_sha 自己整合）
- [ ] 埋め込み公開鍵集合（current + previous, 鍵ローテ）
- [ ] downgrade 防止（vcode 比較）

**Phase 2: graceful restart 経路**
- [ ] `/proc/self/exe` 解決 → fd open → fstat 権限チェック
- [ ] L1 検証 → `fexecve`（TOCTOU 排除）
- [ ] core storage シリアライズ → `memfd_create` + seals → fd 渡し
- [ ] 新プロセス: 起動直後 `PR_SET_DUMPABLE=0` 再設定 → read → 即 Zeroize → close
- [ ] ptrace_scope / dumpable の restart 前後一貫性テスト

**Phase 3: L2 fs-verity（オプトイン）**
- [ ] manifest.json + .sig 生成（fsverity_digest をビルドで計算）
- [ ] restart 時 `FS_IOC_MEASURE_VERITY` → 署名済み manifest と照合
- [ ] 非対応環境の縮退（L1 のみで続行）を明示テスト（overlayfs/tmpfs）

**Phase 4: 配布**
- [ ] アーキごと single binary（L1 署名済み）を gh release
- [ ] `SHA256SUMS` + minisign/cosign 添付
- [ ] rpm/deb/apk パッケージ + post-install（fsverity enable, 失敗許容）
- [ ] upgrade で enable 張り直しが走ることの検証
- [ ] 公開鍵 fingerprint のドキュメント記載（TOFU）

**横断（検証）**
- [ ] TOCTOU 差し替えテスト（検証後に別バイナリを置いて fexecve が本物を実行することを確認）
- [ ] 鍵違い / 署名破損 / trailer 破損での拒否テスト
- [ ] downgrade 拒否テスト
- [ ] restart 中の secret 露出窓（coredump/ptrace）が無いことの確認

---

## 付録: 設計上の割り切り（レビュー時の論点）

1. **root は守らない** — 守るならカーネル強制（fs-verity モードA / IMA + Secure Boot）が要り、single binary 配布思想と衝突する。顧客/自社ホスト限定のオプトインに留める。
2. **fs-verity digest は末尾ブロブに入れない** — ファイル全体依存で循環するため manifest 経由。末尾ブロブは body に閉じる値のみ。
3. **L2 は必須にしない** — 非対応環境（コンテナ等）で静かに L1 のみへ縮退。install/restart を止めない。
4. **「同一署名」= 同一鍵であって同一ハッシュではない** — でなければバイナリ更新（本機能の目的）と両立しない。
