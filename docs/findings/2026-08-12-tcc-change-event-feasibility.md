# macOS TCC 権限変化のイベント駆動監視の実現性

- Date: 2026-08-12

## 判明した事実

- `com.apple.tcc.access.changed` という通知名は Apple 製バイナリに実在する。macOS 18.5 と 26.0 beta のバイナリ文字列差分にも含まれ、公開コード検索では Apple プラットフォームの複数コンポーネントによる購読例が確認できる。ただし Apple の公開 API 文書に通知名・発火条件・payload の契約は見つからず、private な実装詳細である。
  - [ipsw-diffs: macOS 18.5 vs 26.0 の SEService バイナリ差分](https://github.com/blacktop/ipsw-diffs/blob/d881e84676308404c6947d0218c11f347a6f3a89/18_5_22F76__vs_26_0_23A5260n/DYLIBS/SEService.md)
  - [iOS 26.1 TCC.framework 逆コンパイル結果](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/PrivateFrameworks/TCC.framework/Support/TCC/TCC_01.mm)
- 公開コードには `DistributedNotificationCenter.default().notifications(named:)` でこの通知を購読し、受信後に個別の権限 API を再評価する実装例がある。Foundation の distributed notification API 自体は公開 API だが、この TCC 通知名は公開 API ではない。
  - [PHTVTCCNotificationService.swift](https://github.com/PhamHungTien/PHTV/blob/d0314b9f2912164939b5d57f53291c0fc55f85a4/Apps/macOS/PHTV/System/PHTVTCCNotificationService.swift)
  - [Apple: DistributedNotificationCenter](https://developer.apple.com/documentation/foundation/distributednotificationcenter)
- C API では Darwin notification center を `CFNotificationCenterGetDarwinNotifyCenter` で取得し、`CFNotificationCenterAddObserver` で文字列名を購読できる。Darwin notification はプロセス間通知だが、Apple の API 契約上 payload は利用できず、callback の object と userInfo は `NULL` である。このため Rust FFI から購読しても、通知だけからサービス名・対象 client・grant/revoke を判定できない。
  - [Apple CFNotificationCenter header](https://github.com/apple-oss-distributions/CF/blob/main/CFNotificationCenter.h)
- SQLite の WAL モードでは、変更は通常 main database ではなく `-wal` に追記され、checkpoint で main database に移る。したがって `TCC.db` 本体だけの vnode/kqueue 監視では変更を即時・完全には捉えられない。
  - [SQLite Write-Ahead Logging](https://sqlite.org/wal.html)
- FSEvents はディレクトリ階層の変更を通知する API であり、変更内容や SQLite transaction commit を通知する API ではない。イベントは合成・遅延され得るため、通知後の状態再評価が必要である。
  - [Apple File System Events Programming Guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/Introduction/Introduction.html)
- TCC database の場所とアクセス制御は macOS の実装詳細であり、FDA 未付与プロセスが `/Library/Application Support/com.apple.TCC/` の vnode/FSEvents を登録・受信できることを保証する公開資料は確認できなかった。
- 調査した公開実装は、通知受信そのものを権限状態とせず、受信後に対象権限の専用 probe を再実行していた。FDA 付与待機を、文書化された TCC change event だけで完結させる OSS の安定した先行実装は確認できなかった。

## 実用的な示唆 / ベストプラクティス

- cache-warden の権限状態の正本は、既存の app bundle re-launch probe の結果にする。非公開通知や filesystem event を grant の証拠として扱わない。
- helper の live 表示では `com.apple.tcc.access.changed` を wake-up hint として購読し、受信時に probe を即時再実行する案は有効である。ただし通知欠落・名称変更に備え、待機期限内の低頻度 fallback probe を残す必要がある。
- `daemon register` の `wait_for_grant` も同じ構造にできる。通知で早く反応し、fallback timer で互換性を保ち、最終判断は probe だけで行う。
- `TCC.db` の filesystem 監視は推奨しない。FDA をまだ持たない時点で監視登録できる保証がなく、`TCC.db`・`TCC.db-wal`・`TCC.db-shm` と親ディレクトリの複数監視、rename/reopen、event coalescing を扱っても通知以上の安定性が得られないためである。
- 実装採否の前に、対象 macOS で次の実機マトリクスを埋める必要がある。
  1. FDA OFF→ON と ON→OFF の各操作で通知が届くか。
  2. 通知が System Settings 操作から何回・何ミリ秒後に届くか。
  3. app helper、通常の非 sandbox CLI、launchd daemon の各プロセスで受信できるか。
  4. `Notification` の object/userInfo が空か、サービスまたは client の情報を持つか。
  5. macOS 14、15、26 の各世代で通知名と挙動が同じか。

## 検証の詳細

### `com.apple.tcc.access.changed` の実在と公開契約

| 項目 | 結果 |
|---|---|
| Apple 製バイナリ中の文字列 | 確認できた |
| macOS 26 世代での文字列 | バイナリ差分で確認できた |
| Apple 公開 API 文書 | 通知名・発火条件・payload の記載を確認できなかった |
| FDA (`kTCCServiceSystemPolicyAllFiles`) 変更時の発火 | 未確認 |
| grant/revoke の両方向 | 未確認 |
| userInfo/object の内容 | 未確認。Darwin C API の公開契約では payload を運べない |
| sandbox 外プロセスでの受信 | 汎用 distributed/Darwin notification API は利用可能だが、この通知の配信対象は未確認 |

考察: 文字列の存在と特定 OS 世代での残存は、安定した API 契約を意味しない。実装する場合は notification name を private implementation detail として局所化し、通知なしでも正しく完了する fallback が必須である。

### 受信 API

| API | 利用形態 | 制約 |
|---|---|---|
| `DistributedNotificationCenter` | Swift/Objective-C から name を指定して購読 | TCC 通知名自体は非公開。受信 payload は実機確認が必要 |
| `CFNotificationCenterGetDarwinNotifyCenter` + `CFNotificationCenterAddObserver` | C ABI のため Rust FFI から利用可能 | Darwin center は payload を運ばない。callback は signal としてのみ使う |
| `notify_register_dispatch` | libnotify の名前付き Darwin notification を dispatch queue で受信 | 通知名の非公開性は変わらず、状態は別途 probe が必要 |

### TCC database のファイル監視

| 項目 | 結果 |
|---|---|
| main database のみ監視 | WAL 追記を即時に捉えないため不十分 |
| `-wal` / `-shm` 監視 | SQLite の補助ファイル lifecycle と rename/reopen を扱う必要がある |
| FSEvents | ディレクトリ変更の wake-up hint にはなるが transaction commit の通知ではない |
| kqueue/vnode | 対象を open できることが前提。FDA 未付与状態で system TCC directory/file を開けるか未確認 |
| FDA 未付与状態でのイベント受信 | 公開資料からは確認できなかった |

考察: filesystem 監視を追加しても、結局は event 後に probe が必要である。さらに監視自体が TCC の保護対象へ依存するため、FDA 取得待ちの bootstrap 経路としては循環的である。

### 公開実装の傾向

GitHub の exact string 検索では、Apple バイナリの解析成果、通知名カタログ、`DistributedNotificationCenter` の購読例が見つかった。確認できた購読例は、通知受信後に Accessibility など個別 API の状態を再取得する設計であり、notification payload を権限状態として信頼していない。

FDA については公開された専用 status API がなく、実際に保護対象へアクセスする probe や、定期的な再確認を使う実装が中心だった。今回の文献調査だけでは、FDA change notification の発火を macOS 複数世代で保証できる先行実装は見つからなかった。
