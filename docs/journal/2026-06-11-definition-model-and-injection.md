# definition-model-and-injection: 定義モデル・注入・dry-run・OTP の設計と実装

- Date: 2026-06-11

## 何をしたか

Fable セッション（authsock 移植完遂後の引き継ぎ）で、kawaz との対話設計 → DR 起票 →
Opus サブエージェント委譲による実装、を 1 日で 4 周回した。設計 4 本（DR-0013〜0016）、
リリース 5 本（v0.8.1〜v0.12.0）。

| リリース | 内容 | DR |
|---|---|---|
| v0.8.1 | core dump 抑制（RLIMIT_CORE=0、fail-open） | port plan §3 判断 5(a) |
| v0.8.2 | 定義レジストリ（core）+ CLI help 階層化 | DR-0014 §2 |
| v0.9.0 | `kv define` / set static 化 / `--source op://` / config lazy 化 + authsock 自動 eager | DR-0014 |
| v0.10.0 | `--defs` 一括 define + 定義永続化（opt-in、値は書かない） | DR-0014 §4 |
| v0.11.0 | `run` / `inject` / dry-run（マスク検証、極性切替） | DR-0013 / DR-0015 |
| v0.12.0 | OTP 値型（seed write-only、デーモン側 TOTP 導出） | DR-0016 |

## 設計議論の流れ（kawaz との対話で確定した順）

1. `cache-warden://KEY` 注入の設計（DR-0013）→ argv 非置換（ps 漏洩）・出力マスキング見送りを判断
2. 「get でも --command 使えない？」→ get-or-init 案 → **define 動詞分離**へ収束（DR-0014）。
   define は登録のみで実行しない、という分離が set --command の eager 実行問題も同時に解いた
3. 参照クエリ（`?command=`）案 → データ→コード境界の懸念 → opt-in 後送り、`--defs` ファイルが主経路に
4. 永続化は「定義だけ」（値は捨てる）、config 優先マージ
5. reveal/masked の極性 → 非対称案を kawaz が却下（認知負荷）→ **統一 reveal + `--dry-run` +
   env/config で文脈ごと切替**（DR-0015）。dry-run は full-chain 検証（浅い検証は嘘をつく）
6. op help を眺めていて OTP に着想（DR-0016）→ seed write-only という op より強い性質を獲得

## ハマり所・発見と解決

- **`op read` に `--reveal` は存在しない**（op 2.34.0 実機確認）。DESIGN の config 例が
  実行時エラーになる argv を例示していた → 修正。op の masking は表示系（`op item get`）の機能で、
  移送系（read / run env / inject）は常に実値。`op run` の「masked」の記憶は子プロセス
  **出力**のマスキングのこと
- **lazy 化 × authsock の footgun**: `[kv.*]` lazy デフォルト化で authsock 参照鍵が黙って
  socket から消える（`build_registry` は resident 値が前提）→ `preload` 手書き要求ではなく
  **socket の `keys` 宣言自体を preload の意思表示とみなして自動 eager** に（DR-0004 不変条件を維持）
- **バイナリ安全の実バグ**: 参照スキャンを `from_utf8_lossy` 経由で書くと U+FFFD 置換で
  オフセットがずれる → 生バイト走査に修正（サブエージェントが TDD で検出）
- **`--command` は以降全部を argv として消費**するので TTL フラグは前置。DESIGN 例と help の
  usage を「[OPTIONS] が先、--command が最後」に修正
- **サブエージェントの API 接続死**: define 実装の 1 人目が ConnectionRefused で途中死
  （wire/handler のみ残してコンパイル不能）→ 2 人目に「jj diff で残骸精査 → 活かすか書き直すか
  判断せよ」で引き継ぎ成功
- **TOTP の独立検証**: 実装の正しさを RFC ベクタに加えて python 独立実装と実機突き合わせで確認

## 追記（同日夜、kawaz リモート中の自律作業分）

- **zsh 補完** (v0.12.0 後): `cache-warden.plugin.zsh` + `completions/_cache-warden` +
  zpty 実補完テスト。sheldon (`~/.config/sheldon/plugins.toml`、compinit エントリより前) に登録済み
- **key 層 allowed_processes** (v0.13.0): `[kv.NAME].allowed_processes`、config 専用
  （define 自己申告を封じる）、socket 層と直列・fail-closed。DR-0012 に key 層節を補追
- **パリティ検証準備**: `docs/runbooks/parity-verification.md`（[無人可]/[同席要] タグ付き）+
  実値入り並走 config 案はリポ外 `~/.config/cache-warden/parity-draft.toml`
- **重要訂正（kawaz 指摘）**: 準備エージェントが warden の `[auth] method=command` を
  「op への署名都度委譲」と誤読 → 実際は**ユーザ定義認証フロー**（cache-warden の
  `[auth].command` と同概念）で、署名モデルは両者とも「PEM fetch + ローカル署名」で同型。
  実差は**キャッシュ寿命のみ**（warden は TTL 未配線で実質無期限）。TouchID 比較の期待値を
  「キャッシュ生存中は両者 0 回、cache-warden の失効時認証増は設計どおり」に書き直した
- **anti-debug (b)** (v0.14.0): PT_DENY_ATTACH (macOS) / PR_SET_DUMPABLE=0 (Linux、attach
  防御目的)。`[daemon].allow-debug-attach` で opt-out 可、無効化時は警告。macOS 実機で
  attach 拒否を手動確認済み。残る anti-debug は (c) DYLD 検出のみ（優先度低）

## 運用メモ（次セッション向け）

- 体制: メイン Fable（設計・監査・統合）+ Opus サブエージェント（実装、TDD、commit しない）。
  監査で毎回 1〜2 件の実質的指摘が出た（トップレベル help の極性不統一 / authsock footgun /
  status 型表示の落ち）ので、**監査工程は省略しない**こと
- 残タスク（handoff journal 由来、未着手）: パリティ実機検証（Phase 2、kawaz 同席要）/
  key 層 allowed_processes 🟡 / op agent socket 高速路 🟡 / ビルトイン TouchID 🔴 /
  anti-debug (b)(c) 🔴 / privsep 🔴 / 他ベンダ KeySource（`--source` scheme テーブルが受け皿）
- 新規の将来候補: 参照のインライン define（opt-in、DR-0014 §5）/ zsh 補完（CLI 面が安定した今が頃合い）

## 関連

- [DR-0013](../decisions/DR-0013-secret-reference-injection.md) / [DR-0014](../decisions/DR-0014-kv-definition-model.md) / [DR-0015](../decisions/DR-0015-dry-run-verification-mode.md) / [DR-0016](../decisions/DR-0016-otp-value-type.md)
- [2026-06-11-authsock-port-and-fable-handoff.md](./2026-06-11-authsock-port-and-fable-handoff.md) — 前セッションからの引き継ぎ元
- [DESIGN-ja.md](../DESIGN-ja.md) — 全変更を反映済み
