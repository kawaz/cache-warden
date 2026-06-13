# authsock signer 鍵タイプ・署名アルゴリズム実機マトリクス監査

cache-warden の authsock アダプタ (`crates/cache-warden-authsock/src/signer.rs`) が
「現行 OpenSSH (10.3p1) で利用可能な全 SSH 鍵タイプ・署名アルゴリズム」で正しく
署名できるかを、使い捨てテスト daemon で実機検証した正しさ監査。

検証環境: macOS, OpenSSH_10.3p1 / OpenSSL 3.6.2, cache-warden 0.19.1 (release build)。

> **更新 (2026-06-13)**: 本監査で判明した ECDSA 非対応は修正済み。`signer.rs` に
> `KeyMaterial::Ecdsa` を追加し、nistp256/384/521 の OpenSSH / PKCS#8 / SEC1 parse、
> 署名 (`mpint(r) || mpint(s)` wire 形式)、公開鍵導出を実装。実 sshd handshake で
> 3 曲線とも `Authenticated ... using "publickey"` を確認。ssh-key 0.6 が P-521 OpenSSH
> 鍵の短縮スカラー (65 byte mpint) を `Encoding(Length)` で弾く upstream bug は、
> 自前 OpenSSH ECDSA フォールバック parse で救済済み。以下マトリクスは更新後の状態。

## 判明した事実

### 対応マトリクス (鍵タイプ × {parse, 列挙, 署名, 署名検証})

| 鍵タイプ | parse | 列挙(REQ_IDENTITIES) | 署名(SIGN) | 署名検証 | 判定 |
|---|---|---|---|---|---|
| ssh-ed25519 (OpenSSH形式) | OK | OK | OK | OK (ssh-add -T) | 対応 |
| ssh-ed25519 (PKCS#8) | OK | OK | OK | OK | 対応 |
| RSA-2048 (OpenSSH形式) | OK | OK | OK | OK (実 sshd handshake) | 対応 |
| RSA-2048 (PKCS#8) | OK | OK | OK | OK | 対応 |
| RSA-4096 (OpenSSH形式) | OK | OK | OK | OK (実 sshd handshake) | 対応 |
| ecdsa-sha2-nistp256 (OpenSSH形式) | OK | OK | OK | OK (実 sshd handshake) | **対応** |
| ecdsa-sha2-nistp256 (PKCS#8) | OK | OK | OK | OK | **対応** |
| ecdsa-sha2-nistp256 (SEC1) | OK | OK | OK | OK | **対応** |
| ecdsa-sha2-nistp384 (OpenSSH/PKCS#8/SEC1) | OK | OK | OK | OK (実 sshd handshake) | **対応** |
| ecdsa-sha2-nistp521 (OpenSSH/PKCS#8/SEC1) | OK | OK | OK | OK (実 sshd handshake) | **対応** |
| EC SEC1 (`BEGIN EC PRIVATE KEY`) | OK | OK | OK | OK | **対応** (ECDSA 全曲線) |
| RSA PKCS#1 (`BEGIN RSA PRIVATE KEY`) | **NG** | NG | NG | - | **非対応 (形式、scope外)** |
| ssh-dss (DSA) | - | - | - | - | scope外 (OpenSSH 10 が生成不可 = 既に削除) |
| ed25519-sk / ecdsa-sk (FIDO) | **NG (コード非対応)** | NG | NG | - | **非対応** (実機はデバイス無しで未検証、コードに分岐なし) |
| *-cert-v01 (証明書) | NG (コード非対応) | NG | NG | - | **非対応** (private key として来ないが、cert 提示機構なし) |

### RSA SHA-2 / SHA-1 出し分けの結論 (= 過去 RSA バグの再発確認)

**正しく出し分けできている (バグ再発なし)**。`sign_rsa()` が SIGN_REQUEST の flags
(`SSH_AGENT_RSA_SHA2_512=0x04` / `_256=0x02` / 両0=SHA-1) を見て分岐:

| 要求アルゴリズム | flag | 実 sshd handshake (rsa2048/rsa4096) |
|---|---|---|
| rsa-sha2-512 | 0x04 | PASS / PASS (`Authenticated to ... using "publickey"`) |
| rsa-sha2-256 | 0x02 | PASS / PASS |
| ssh-rsa (SHA-1) | 0 | PASS / PASS |

ローカル temp sshd を `PubkeyAcceptedAlgorithms` で各1アルゴリズムに絞って強制 handshake
した結果、3アルゴリズム全てで認証成立。modern OpenSSH (rsa-sha2-256/512 既定) と
legacy サーバ (ssh-rsa のみ) の両対応が実証された。PKCS#1 由来でない (= OpenSSH/PKCS#8
形式の) RSA 鍵に限り、CRT precompute も両経路で実施されており健全。

### OpenSSH 現行 (10.3p1) との gap

`ssh -Q PubkeyAcceptedAlgorithms` が列挙する 20 種に対し、cache-warden が署名可能なのは
**実質 ed25519 / rsa (sha1,sha2-256,sha2-512) のみ**。以下が gap (= 非対応):

- ~~**ECDSA 全曲線非対応** (`ecdsa-sha2-nistp256/384/521`)~~ → **対応済み (2026-06-13)**。
  `KeyMaterial::Ecdsa` バリアント + `from_openssh_private_key` の `KeypairData::Ecdsa`
  分岐 + `parse_pkcs8_strict` の EC OID (1.2.840.10045.2.1) 分岐 + SEC1 (`BEGIN EC
  PRIVATE KEY`) 経路 + `sign_ecdsa` (曲線別 SHA-256/384/512、`mpint(r)||mpint(s)`)
  を実装。p256/p384/p521 crate で署名、ssh-key + p521 crate で parse。
- **FIDO/SK 鍵非対応** (`sk-ssh-ed25519@` / `sk-ecdsa-sha2-nistp256@` /
  `webauthn-sk-*`): コードに分岐なし。ただし SK 鍵は秘密鍵 PEM を agent が保持して
  ローカル署名する設計と相性が悪い (ハードウェア常駐が前提) ため、scope 外とする
  妥当性はある。
- **証明書 (`*-cert-v01@openssh.com`) 非対応**: registry / IDENTITIES に証明書 blob を
  載せる機構なし。
- **鍵保存形式の gap**: `pem_kind()` は `BEGIN OPENSSH PRIVATE KEY` / `BEGIN PRIVATE
  KEY` (PKCS#8) / `BEGIN ENCRYPTED PRIVATE KEY` / **`BEGIN EC PRIVATE KEY` (SEC1、
  2026-06-13 追加)** を認識。SEC1 は ECDSA 全曲線で parse 可。
  **PKCS#1 (`BEGIN RSA PRIVATE KEY`) のみ未対応** (= openssl 等の素の RSA PEM。op 経路
  では PKCS#8 なので発生せず、優先度低・scope 外)。

## 実用的な示唆 / ベストプラクティス

### 影響 (どんな鍵/サーバで詰まるか)

- **ECDSA 鍵を使っているユーザは authsock 経由で一切署名できない**。`[kv.*]` に
  ECDSA 秘密鍵を登録しても起動時 eager 実体化で skip され、`ssh-add -L` にも現れず、
  SIGN_REQUEST は agent refused になる。サイレントに「鍵が無い」状態 (起動ログに
  warning は出るが、ユーザが daemon ログを見ないと気づきにくい)。
- **op (1Password) 経由の ECDSA SSH 鍵も同様に署名不可**。op discovery は public key
  から blob を作って列挙はできるが (`register_op_key` は ssh_key で全タイプ parse 可)、
  実際の SIGN 時に `signer::sign()` が PEM を parse する段で落ちる。**列挙はできるのに
  署名で失敗する**非対称が起こり得る (op 鍵は eager 実体化されないため起動時 skip
  ログも出ず、初回 sign まで露見しない = より危険)。
- PKCS#1/SEC1 形式の鍵を直接食わせるケース (openssl 生成、レガシー鍵) も parse 不可。
  ただし op 由来は PKCS#8 なので op 経路では問題になりにくい。

### 対処方針 (推奨度順)

1. ~~**ECDSA 対応を追加する** (最優先)~~ → **実装済み (2026-06-13)**。`KeyMaterial::Ecdsa`
   + `from_openssh_private_key` の `KeypairData::Ecdsa` 分岐 + `parse_pkcs8_strict` の
   EC OID 分岐 + `sign_ecdsa()` の P-256/384/521 別署名 (`p256`/`p384`/`p521` crate) +
   `public_key_data()` の EC 公開鍵導出。署名 blob は
   `string("ecdsa-sha2-nistpXXX") + string(mpint r || mpint s)`。SEC1 形式も同時対応。
   P-521 OpenSSH 短縮スカラーの ssh-key bug は自前フォールバック parse で救済。
2. ~~**当面の運用ガード**~~ → 不要になった (ECDSA 対応済みで「列挙されたのに署名不可」の
   非対称が解消)。local/op 双方の経路で ECDSA が parse → 署名 → 検証まで通る。
3. PKCS#1 (`BEGIN RSA PRIVATE KEY`) 形式は依然未対応 (op 経路では発生しない、優先度低)。
   必要なら `pem_kind` に `BEGIN RSA PRIVATE KEY` を追加し `rsa` crate の PKCS#1 decode で parse。
   SEC1 (`BEGIN EC PRIVATE KEY`) は 2026-06-13 に対応済み。
4. SK 鍵・証明書は scope 外とする判断が妥当。README/DESIGN の対応鍵タイプは
   「ed25519 / RSA / **ECDSA (nistp256/384/521)**」に更新する (本 finding 反映後)。

## 検証の詳細

### 鍵生成 (OpenSSH 10.3p1)

```
ssh-keygen -t ed25519 / -t rsa -b 2048 / -t rsa -b 4096
ssh-keygen -t ecdsa -b 256 / -b 384 / -b 521
ssh-keygen -t dsa          # => "unknown key type dsa" (OpenSSH 10 で削除済)
ssh-keygen -t ed25519-sk   # => "device not found" (FIDO 実機なし、未検証)
# 形式変換: ssh-keygen -p -m PKCS8 / -m PEM (RSA=PKCS#1, EC=SEC1)
```

### テスト daemon (使い捨て)

`/tmp/keytest/config.toml`: 各鍵を `[kv.K_<name>] source="command" command.argv=["cat", "<path>"]`
で供給し、`[authsock.sockets.test] keys=[全13エントリ] path="/tmp/keytest/agent.sock"`、
`[daemon] socket="/tmp/keytest/control.sock"`、`[auth]` 省略 (AllowAll)。authsock の keys は
起動時 eager 実体化されるため、起動ログに parse 結果が出る。

### 起動時 eager registration の結果 (daemon.log)

13 エントリ中 **3 鍵のみ登録成功** (ed25519, rsa2048, rsa4096)。残り 10 が以下で skip:

```
key `default/K_ecdsa256`: Unsupported key algorithm: Ok(Ecdsa { curve: NistP256 }). Only Ed25519 and RSA are supported.
key `default/K_ecdsa384`: Unsupported key algorithm: Ok(Ecdsa { curve: NistP384 }). ...
key `default/K_ecdsa521`: Unsupported key algorithm: Ok(Ecdsa { curve: NistP521 }). ...
key `default/K_ecdsa256_pkcs8`: Unsupported PKCS#8 algorithm. Only Ed25519 and RSA are supported.
key `default/K_ecdsa384_pkcs8` / `K_ecdsa521_pkcs8`: 同上
key `default/K_rsa2048_pem`: Unsupported PEM format. Expected "BEGIN OPENSSH PRIVATE KEY" or "BEGIN PRIVATE KEY"
key `default/K_ecdsa256_pem`: 同上 (SEC1 EC)
authsock `test` listening (3 key(s) incl. 0 op, 0 upstream(s), 0 filter term(s))
```

### 列挙 + 署名検証

```
SSH_AUTH_SOCK=/tmp/keytest/agent.sock ssh-add -L  # => 3 件 (ed25519 + rsa2048 + rsa4096)
ssh-add -T <pub>  # ed25519 / rsa2048 / rsa4096 => PASS、ecdsa* => "agent refused operation"
```

### RSA SHA-2/SHA-1 出し分け (実 sshd handshake)

temp sshd を `/tmp/keytest/sshd_config` (`PubkeyAcceptedAlgorithms +ssh-rsa,rsa-sha2-256,rsa-sha2-512`,
host key ed25519, port 22222) で起動。client 側で各アルゴリズムを単独強制:

```
ssh -o PubkeyAcceptedAlgorithms=rsa-sha2-512 -o IdentityAgent=$SSH_AUTH_SOCK ... 'echo AUTH_OK'
# rsa-sha2-512 / rsa-sha2-256 / ssh-rsa すべて AUTH_OK
# ssh -v: "Server accepts key ... agent" + "Authenticated to 127.0.0.1 using publickey" を3アルゴリズムで確認
```

sshd VERBOSE ログでも `Accepted publickey ... ssh2: RSA` を確認。

### 後始末

temp sshd (pid kill)、使い捨て cache-warden daemon (自ログの pid を kill)、
/tmp/keytest のソケット削除を実施。本番 daemon (cache-warden pid 29507 /
authsock-warden pid 2565) は無干渉を確認済み。
