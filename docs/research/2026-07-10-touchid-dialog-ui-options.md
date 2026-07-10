# TouchID + カスタム情報 dialog の実現手段調査 (custom-touchid-dialog 用)

issue `2026-06-22-custom-touchid-dialog` の設計判断材料。2026-07-10 調査
(crates.io / 一次資料 OSS ソース / Apple doc)。

## 判明した事実

1. **LocalAuthentication の TouchID シート自体はカスタマイズ不能**。
   `LAContext.evaluatePolicy` で変えられるのは `localizedReason` (1 行) /
   `localizedCancelTitle` / `localizedFallbackTitle` のみ。プロセスツリー等の
   リッチ情報をシートに埋め込む API は存在しない。リッチ表示が要件なら
   「自前 window を出す → その上で evaluatePolicy」の **2 段構成が必須**
2. **Rust から TouchID を叩く binding は実用水準で存在する**:
   `objc2-local-authentication` v0.3.2 (madsmtm/objc2 ecosystem、objc2 本体は
   2026-02 更新・DL 7,800 万件で活発)。標準 TouchID 認証だけならこれで足りる
3. **secretive (maxgoedjen/secretive) は「リッチ pre-auth dialog」を実装していない**。
   `SigningRequestTracer.swift` で呼び出し元の pid / path / 署名検証 / 親チェーンを
   収集するが (= 情報収集部は本 issue の直接の参考になる)、表示は
   `localizedReason` に app 名 + secret 名を圧縮 + 署名**後**の
   UNUserNotificationCenter バナーのみ。署名前フック protocol
   (`speakNowOrForeverHoldYourPeace`) は存在するが空実装
4. **1Password SSH agent は「承認ウィンドウ → TouchID」の 2 段フロー** (公式 doc
   記載)。ただし closed source で実装方式は確認不能。常駐 GUI アプリ本体が
   承認ウィンドウを持つ形とみられる (推測)
5. **daemon プロセス内で AppKit UI を出すのは設計コストが高い**: AppKit は
   NSApplication run loop (メインスレッド占有) を要求し、tokio ベース daemon と
   メインスレッドを取り合う。UI を別プロセスに切り出す方が自然

## 実用的な示唆 — 選択肢比較

| 選択肢 | 実現性 | 依存 | メンテリスク | 親和性 |
|---|---|---|---|---|
| A. `localizedReason` に要約 1 行を圧縮 (secretive 方式) | 高・即実装可 | objc2-local-authentication のみ | 低 | 高。ただし「プロセスツリー表示」の受け入れ条件は満たせない |
| B. daemon 内 objc2-app-kit で NSAlert | 中 | 中 | 低 | 低〜中 (run loop 争奪) |
| C. Swift/AppKit helper を .app 同梱、spawn + JSON IPC で custom dialog → 内部で LAContext | 中 (OSS 直接前例は未発見) | Swift toolchain + build 統合 | 中 (2 言語 build) | 高 (notarized .app 構成に helper 追加は自然) |

- 受け入れ条件 (プロセスツリー表示 / 詳細展開 / guard 評価結果表示) を満たすのは
  実質 **C** のみ。**A は C までの中間段として先行実装する価値がある**
  (crate 依存 1 つで「どの key を誰が要求」の 1 行は出せる = 現状の白紙委任よりは前進)
- B は不採用推奨 (メインスレッド設計の歪みが大きい)
- C の PoC 論点: helper の起動レイテンシ、dialog 表示中の peer exit 処理
  (issue 記載)、1Password dialog との二重表示回避

## 検証の詳細

- crates.io 実測: objc2-local-authentication v0.3.2 (2025-10-04, DL 102k) /
  objc2 v0.6.4 (2026-02-26, DL 78.3M) / objc2-app-kit v0.3.2 (DL 38.5M)。
  代替 apple-localauthentication v0.3.5 (2026-06-06, DL 4.7k、小規模) /
  localauthentication-rs v0.1.0 (2023 年から stale、非推奨)
- secretive ソース確認 (一次資料): SigningRequestTracer.swift (sysctl KERN_PROC_PID +
  proc_pidpath + SecCodeCreateWithPID / SecCodeCheckValidity)、
  SecureEnclaveStore.swift (localizedReason = appName + secretName のみ)、
  Notifier.swift (事後バナー、pre-auth フックは空実装)
- 1Password: https://developer.1password.com/docs/ssh/agent/ (2 段フロー記載、
  実装は closed source で未確認)
- 未確認事項: 「daemon が UI helper を spawn して JSON 対話」する OSS の直接前例
  (見つからず)。1Password の実バイナリ構成 (bundle 内 helper の有無) は
  実機 `otool -L` / bundle 走査で確認可能だが未実施
