# Runbook: Apple 署名・notarization 用 GitHub Secrets のセットアップ

- Last Updated: 2026-06-12

cache-warden の release ワークフロー (`.github/workflows/release.yml`) の macOS ジョブが
codesign / notarization に使う 6 種の GitHub Secrets を、cache-warden 用に **新規発行して投入**する手順。
設計の根拠は [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) (§3)。

> **secrets はプロダクト別** (DR-0020 確定): warden の secrets を使い回さず cache-warden 用に
> 発行する。漏洩時の rotate 単位と影響範囲がプロダクトに閉じ、warden archive 時にも独立する。

これは Apple ID / Keychain Access の手操作が必要なため **kawaz の手作業**。GitHub Actions からは
同名で参照される (workflow 側の変更は不要)。

## 投入する Secret 一覧

| Secret | 値の性質 | 発行/取得元 |
|---|---|---|
| `APPLE_ID` | 共通値 | Apple ID のメールアドレス |
| `APPLE_TEAM_ID` | 共通値 | Apple Developer の Team ID (10 文字) |
| `APPLE_APP_SPECIFIC_PASSWORD` | **cache-warden 用に新規発行** | appleid.apple.com |
| `APPLE_CERTIFICATE_BASE64` | p12 を base64 化 | Keychain Access からエクスポート |
| `APPLE_CERTIFICATE_PASSWORD` | p12 エクスポート時に設定 | 自分で決める |
| `APPLE_SIGNING_IDENTITY` | 共通値 | `Developer ID Application: 名前 (TEAMID)` |

`APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_SIGNING_IDENTITY` は Team の共通値なので warden 投入時の値を
そのまま再利用してよい。**プロダクト別にする主対象は `APPLE_APP_SPECIFIC_PASSWORD`** (rotate 単位)。
証明書 (p12) は Team の既存 Developer ID Application 証明書を流用できるが、p12 は再エクスポートする。

## 1. App-Specific Password の新規発行 (cache-warden 用)

1. <https://appleid.apple.com> にサインイン
2. 「サインインとセキュリティ」→「App 用パスワード」
3. 「App 用パスワードを生成」→ ラベルに **`cache-warden notarytool`** 等の識別名を入れる
   (warden 用と区別できる名前にする = 個別 rotate のため)
4. 表示された `xxxx-xxxx-xxxx-xxxx` 形式のパスワードを控える (この画面を閉じると再表示できない)

```bash
gh secret set APPLE_APP_SPECIFIC_PASSWORD --repo kawaz/cache-warden
# プロンプトに xxxx-xxxx-xxxx-xxxx を貼り付けて Enter
```

## 2. Developer ID Application 証明書を p12 でエクスポート

Team に既存の「Developer ID Application」証明書がある前提 (warden で使っているもの)。

1. **Keychain Access** を開く
2. 「ログイン」キーチェーン → 「自分の証明書」カテゴリ
3. `Developer ID Application: 名前 (TEAMID)` を展開し、**証明書と秘密鍵の両方**を選択
4. 右クリック →「2 項目を書き出す...」→ フォーマット **「個人情報交換 (.p12)」**
5. 保存先を決め、**エクスポートパスワード**を設定 (これが `APPLE_CERTIFICATE_PASSWORD` になる)

```bash
# p12 を base64 化して secret に投入 (改行なし)
base64 -i /path/to/cache-warden-cert.p12 | gh secret set APPLE_CERTIFICATE_BASE64 --repo kawaz/cache-warden

# エクスポート時に設定したパスワード
gh secret set APPLE_CERTIFICATE_PASSWORD --repo kawaz/cache-warden
# プロンプトにパスワードを貼り付けて Enter
```

> エクスポートした p12 は secret 投入後に削除してよい (`rm /path/to/cache-warden-cert.p12`)。
> リポや `~/.ssh` 等に残さない。

## 3. 共通値の投入

```bash
# Apple ID (メールアドレス)
gh secret set APPLE_ID --repo kawaz/cache-warden
# プロンプトに Apple ID を入力

# Team ID (10 文字。developer.apple.com の Membership details で確認)
gh secret set APPLE_TEAM_ID --repo kawaz/cache-warden

# 署名 identity の完全名。下記コマンドで自分のマシンの値を確認できる
security find-identity -v -p codesigning | grep "Developer ID Application"
# 例: "Developer ID Application: Yoshiaki Kawazu (XXXXXXXXXX)"
gh secret set APPLE_SIGNING_IDENTITY --repo kawaz/cache-warden
# 上記で確認した "Developer ID Application: ..." 文字列を貼り付け
```

## 4. 投入確認

```bash
gh secret list --repo kawaz/cache-warden
# APPLE_ID / APPLE_TEAM_ID / APPLE_APP_SPECIFIC_PASSWORD /
# APPLE_CERTIFICATE_BASE64 / APPLE_CERTIFICATE_PASSWORD / APPLE_SIGNING_IDENTITY
# の 6 種が並ぶことを確認
```

6 種が揃えば次回の `Cargo.toml` version bump → main push で macOS ジョブの署名・notarization が通る。
未投入のまま release が走ると macOS ジョブが署名ステップで失敗する。

## トラブルシュート

- notarize が `403 agreement missing` → [release-notarization-403](./release-notarization-403.md)
- `Invalid credentials` → App-Specific Password の失効/タイポ。手順 1 を再実行して再投入
- codesign が `errSecInternalComponent` 等 → p12 のエクスポート不備 (秘密鍵が含まれていない)。
  手順 2 で「証明書と秘密鍵の両方」を選択し直す

## ローテーション / 廃止

- App-Specific Password を rotate するとき: appleid.apple.com で旧パスワードを無効化 → 手順 1 で再発行
- 証明書を入れ替えるとき: 手順 2 を再実行して `APPLE_CERTIFICATE_BASE64` /
  `APPLE_CERTIFICATE_PASSWORD` を更新
- cache-warden 廃止時: `gh secret delete <NAME> --repo kawaz/cache-warden` を 6 種分。
  共通値 (APPLE_ID 等) は他プロダクトに影響しないが、App-Specific Password は appleid.apple.com 側でも無効化する

## 関連

- [DR-0020](../decisions/DR-0020-macos-signing-and-app-bundle.md) — 署名・notarization・.app バンドルの設計 (secrets はプロダクト別)
- [release-notarization-403](./release-notarization-403.md) — notarize の 403 診断
- `.github/workflows/release.yml` — secrets を消費する macOS ジョブ
