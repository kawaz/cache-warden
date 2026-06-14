# op CLI 失敗種別の区別可能性調査

DR-0022 案 C の前提調査 (A-3c)。op の exit code / stderr で失敗種別を区別できるかを
実機観測とコード読解で確認した。

調査環境: macOS 25.5.0, op 2.34.1 (Homebrew), cache-warden main ブランチ (2026-06-14)。

---

## 判明した事実

### 1. 現状コードの error mapping (cache-warden 側)

#### `RealOpClient::run` (`crates/cache-warden-authsock/src/op.rs:159-170`)

```rust
fn run(&self, args: &[&str], what: &str) -> Result<Vec<u8>> {
    let output = self.command().args(args).output().map_err(|e| {
        Error::KeyStore(format!("failed to execute op CLI: {e}. ..."))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::KeyStore(format!("{what} failed: {}", stderr.trim())));
    }
    Ok(output.stdout)
}
```

- **exit code は保存しない**。`output.status.success()` による 0/非 0 の二値判定のみ
- **stderr は error message に含める**。ただし `Error::KeyStore(String)` の単一 variant に flatten される。カテゴリ情報は variant として保存されない
- spawn 失敗 (op not in PATH) は `map_err` で同じ `Error::KeyStore` に変換される。authsock 層では exit code も失敗種別も完全に消える

#### core `RunError` (`crates/cache-warden/src/source.rs:162-216`)

core 経路 (`__authsock-op-private-key` サブコマンド → `CommandRunner::run`) では:

```rust
pub enum RunError {
    SpawnFailed { program: String, reason: String },
    NonZeroExit { code: Option<i32>, stderr_len: usize },
    EmptyOutput,
    NoProgram,
    Timeout { elapsed: Duration },
}
```

- **exit code は `code: Option<i32>` として保存される** (`NonZeroExit`)
- **stderr 内容は完全に捨てる** (byte 長 `stderr_len` のみ記録)。設計コメントに「failing secret-fetch command may print partial secret material」とあり、意図的な redaction
- `SpawnFailed` は spawn 失敗 (PATH 不在など) を他と区別する variant として存在

#### `op_private_key.rs` (`crates/cache-warden-cli/src/commands/op_private_key.rs:51-58`)

```rust
let pem = match fetch_op_private_key(&client, &item_id) {
    Ok(pem) => pem,
    Err(e) => {
        eprintln!("{NAME}: op private key fetch failed for item `{item_id}`: {e}");
        return Err(...);
    }
};
```

stderr に `{e}` (= `Error::KeyStore` の message 文字列、op の stderr を含む) を出力。**op の stderr が daemon log に再露出する**。ただし Rust の caller にとって型情報は失われている (String のみ)。

### 2. op CLI の実機観測 (在席不要範囲)

`op 2.34.1` で実測。すべて `[ERROR]` prefix を含む行が stderr に出力され、stdout は失敗時に空。

| 失敗種別 | 実行コマンド | exit | stderr (実測) |
|---|---|---|---|
| vault 不存在 | `op item get dummy --vault nonexistent_xyz` | **1** | `[ERROR] "nonexistent_xyz" isn't a vault in this account. Specify the vault with its ID or name.` |
| vault 不存在 (item list) | `op item list --vault nonexistent_xyz` | **1** | 同上 |
| item 不存在 (vault あり) | `op item get nonexistent_abc --vault Private` | **1** | `[ERROR] "nonexistent_abc" isn't an item in the "Private" vault. Specify the item with its UUID, name, or domain.` |
| item 不存在 (vault なし) | `op item get nonexistentitemid123456789abc` | **1** | `[ERROR] "nonexistentitemid123456789abc" isn't an item. Specify the item with its UUID, name, or domain.` |
| account 不存在 | `op item get dummy --account nonexistent.1password.com` | **1** | `[ERROR] error initializing client: found no accounts for filter "nonexistent.1password.com"` |
| not signed in (whoami) | `op whoami` (app integration 無効時) | **1** | `[ERROR] account is not signed in` |
| TouchID 待ちで kill | `timeout 3 op item list ...` (session 切れ) | **124** (SIGTERM) | (なし — プロンプト待ち中に kill) |

**EXIT:0 は stdout あり、EXIT:1 は stdout なし (常に空)**。

### 3. op CLI の exit code 体系 (公開ドキュメント調査)

`op --help`、`op item get --help`、`op signin --help` には **exit code の体系が記述されていない**。man page も存在しない (`man -w op` → no man page)。

公式ドキュメント (https://developer.1password.com/docs/cli/) は web fetch 禁止制約のため未確認。実機観測から:

- **exit code は成功 = 0 / 失敗 = 1 の二値のみ**。失敗の種類は exit code で区別不可
- **全失敗が exit:1 を返す** (vault 不在・item 不在・not signed in すべて同一)
- 唯一の例外は **spawn 失敗** (op not in PATH) = `io::Error` でプロセス自体が起動しない (authsock 層でも `Error::KeyStore` に flatten されるが、message に "Is the 1Password CLI installed?" が含まれる)

### 4. stderr による失敗種別の区別可能性

実測値から **stderr regex によるカテゴリ判定は原理的に可能**。

| カテゴリ | stderr 正規表現 | 信頼性 |
|---|---|---|
| vault 不存在 | `isn't a vault in this account` | 高 (実測確認) |
| item 不存在 | `isn't an item` (vault 有無で message が微妙に異なる) | 高 (実測確認) |
| not signed in | `account is not signed in` | 高 (実測確認) |
| account not found | `found no accounts for filter` | 高 (実測確認) |
| TouchID dismiss / cancel | **不明** — op が何を stderr に出すか在席調査が必要 | **未確認** |
| TouchID timeout | **不明** — op 内部 timeout の stderr が不明 | **未確認** |
| ネット一時失敗 | **不明** — connectivity error の message が不明 | **未確認** |

**在席要の未確認項目**: TouchID dismiss / cancel / timeout、ネット一時失敗の 3 ケースは実際に TouchID プロンプトを発生させないと stderr が取得できない。本調査では実施しない。

### 5. authsock-warden (前世代) の実装

`~/.local/share/repos/github.com/kawaz/authsock-warden/main/src/keystore/op.rs` を参照。`status.success()` + `stderr.trim()` の同一パターンで、**exit code 保存なし**、**stderr を error message に include するが失敗種別 variant なし**。backoff / retry / sleep の実装は存在しない。

経験知として「前世代も同様に exit code / stderr を失敗種別として保存していない」。

---

## 失敗種別区別可能性マトリクス (結論)

| カテゴリ | exit code で区別 | stderr regex で区別 | 信頼性 | 在席要否 |
|---|---|---|---|---|
| vault 不存在 | **不可** (全部 exit:1) | **可** (`isn't a vault in this account`) | 高 | 不要 (実測済) |
| item 不存在 | **不可** | **可** (`isn't an item`) | 高 | 不要 (実測済) |
| op not signed in | **不可** | **可** (`account is not signed in`) | 高 | 不要 (実測済) |
| account not found | **不可** | **可** (`found no accounts for filter`) | 高 | 不要 (実測済) |
| spawn 失敗 (PATH 不在) | **可** (io::Error 経路) | 可 (error message に "installed?" 含む) | 高 | 不要 |
| TouchID dismiss / cancel | **不可** | **不明** — 在席調査が必要 | 低 | **在席要** |
| TouchID timeout | **不可** | **不明** — 在席調査が必要 | 低 | **在席要** |
| ネット一時失敗 | **不可** | **不明** — 実機調査が必要 | 低 | 条件次第 |

---

## 実用的な示唆

### A. 現状コードで区別できる情報

**authsock 層 (`RealOpClient::run`)**:
- stderr の文字列が `Error::KeyStore(String)` のメッセージに含まれる
- 呼び出し元でこの String に対して正規表現マッチすれば種別判定は「原理的に」可能
- ただし、これは **public API としての種別 enum が存在しない** 状態でのパターンマッチ

**core 層 (`CommandRunner` / `RunError`)**:
- `NonZeroExit { code: Option<i32>, stderr_len }` に exit code は保存されるが…
- **stderr 内容は意図的に捨てられている** (secret material redaction の設計判断)
- core 経路 (= `__authsock-op-private-key` サブコマンド経由) では stderr による種別判定は不可能

### B. 区別実装のコスト見積もり

区別可能にするには:

1. **authsock 層の `RealOpClient::run` に op の exit code 保存を追加** — ただし exit code は全失敗で 1 のため、exit code だけでは無意味
2. **authsock 層の stderr に対して regex マッチで `FailureKind` を判定する関数を追加** — `not_signed_in` / `item_not_found` / `vault_not_found` / `spawn_failed` / `unknown` の enum。TouchID 系と ネット一時失敗は **在席調査で stderr message を確認するまで判定不能**
3. **core 層に伝播させるには `RunError` の設計変更が必要** — 現状 core は stderr を捨てる設計。op 専用 `FailureKind` を別経路で渡す必要がある。または `__authsock-op-private-key` サブコマンドが exit code を種別ごとに変える (exit:2/3/...) 方法があるが、op の exit:1 一択という事実と矛盾なく設計する必要がある

### C. TouchID 系の不確実性が問題の核心

DR-0022 の「TouchID dismiss / cancel」「TouchID timeout」が **最も区別したい** カテゴリ (= 短い backoff で人間の再操作を待つ) であるにもかかわらず、これらの stderr パターンは **本調査では在席調査が必要なため未確認**。

在席要の確認内容:
- TouchID ダイアログを表示させて「キャンセル」した時の stderr と exit code
- `op item list` を実行して TouchID を無視し、op 内部 timeout まで待った時の stderr と exit code

---

## 検証の詳細

### 在席不要の実機確認 (本調査で実施)

```
$ op --version
2.34.1

$ op item get dummy --vault "nonexistent_xyz" --fields public_key --format json
[ERROR] ... "nonexistent_xyz" isn't a vault in this account. ...
EXIT:1

$ op item get "nonexistentitemid123456789abc" --fields public_key --format json
[ERROR] ... "nonexistentitemid123456789abc" isn't an item. ...
EXIT:1

$ op item get nonexistent_item_xyz --vault Private --fields public_key --format json
[ERROR] ... "nonexistent_item_xyz" isn't an item in the "Private" vault. ...
EXIT:1

$ op item get dummy --account "nonexistent.1password.com" --fields public_key --format json
[ERROR] error initializing client: found no accounts for filter "nonexistent.1password.com"
EXIT:1

$ op whoami  # app integration 無効時
[ERROR] account is not signed in
EXIT:1

$ timeout 3 op item list --categories "SSH Key" --format json  # session 切れ状態
EXIT:124  # SIGTERM — TouchID プロンプト待ちでブロック
```

すべての失敗で **stdout は空** (wc -c = 0)、**stderr に `[ERROR]` prefix 行** が出力される。

### 在席要 (= 本調査では未実施)

- TouchID ダイアログを「キャンセル」した時の stderr / exit code
- TouchID 内部 timeout 後の stderr / exit code
- ネット切断状態での `op item list` stderr / exit code

---

## 結論と推奨

### 区別可能性の評価

- **exit code による種別区別: 不可能**。op 2.34.1 は全エラーで exit:1 を返す。spawn 失敗 (io::Error 経路) のみ別扱い (すでに authsock 層で別扱い済)
- **stderr regex による種別区別: 部分的に可能、ただし TouchID 系は未確認**。vault 不在・item 不在・not signed in・account not found は regex で区別可能。**TouchID dismiss / cancel / timeout が最も重要なカテゴリであるにもかかわらず stderr パターンが未確認**

### DR-0022 案 C (per-category backoff) の採否

**採用可否: 条件付き**。TouchID 系の stderr を在席調査で確認してから判断。仮に TouchID dismiss が `[ERROR] user canceled` / `user dismissed` のような区別可能なメッセージを持つならば:

- not signed in → 長め backoff (5 分超、リトライしても無駄)
- vault / item 不存在 → 無期限 (構成エラー、リトライで復帰しない)
- TouchID dismiss / cancel → 短め (5-10 秒、人間の再操作を待つ)
- TouchID timeout → 短め (同上)
- ネット一時失敗 → 短め (数秒、リトライで復帰見込み)

という per-category 設定が理論的には可能。ただし実装コストが高い (`RunError` の設計変更が必要)。

**推奨: DR-0022 は一律 5s で先行確定、TouchID 系 stderr 確認後に別 DR で再評価**

- DR-0022 は一律 5s で確定 (本 DR で完結)
- 在席時に `op item list` をキャンセルして TouchID dismiss の stderr を確認する
- もし区別可能なら DR-0024 候補として per-category backoff を起票
- op の stderr message は op のバージョンアップで変わるリスクがある (= 非公式 API)。この点も per-category 実装の懸念として別 DR で評価する

### 追加調査タスク (在席要)

kawaz が次回 op を使う際 or 在席時にまとめて確認:

```bash
# TouchID dismiss 時の stderr (ダイアログを意図的にキャンセルする)
op item list --categories "SSH Key" --format json 2>/tmp/op_touchid_cancel.txt
# キャンセル後
cat /tmp/op_touchid_cancel.txt; echo "EXIT:$?"
```

この結果が判明した時点で本 findings を更新し、DR-0024 起票の要否を判断する。

---

## 関連

- DR-0022 — 本調査の依頼元 (案 C / Q1)、結論として「一律 5s で確定、TouchID 系 stderr 確認後に再評価」
- `crates/cache-warden-authsock/src/op.rs:159-170` — `RealOpClient::run` (本 findings の対象コード)
- `crates/cache-warden/src/source.rs:162-216` — `RunError` (core 側、stderr 意図的に捨てる)
- `crates/cache-warden-cli/src/commands/op_private_key.rs:51-58` — 失敗時 stderr 出力
- authsock-warden `src/keystore/op.rs` — 前世代の同様パターン (経験知)
