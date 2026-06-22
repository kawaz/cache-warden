---
title: macos-process-inspect crate 切り出し
status: open
category: design
created: 2026-06-22T21:15:48+09:00
last_read:
open_entered: 2026-06-22T21:15:48+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# macos-process-inspect crate 切り出し

## 概要

macOS で **socket 対抗プロセスや任意 pid の出自を多面的に inspect** する Rust crate を切り出す。Pure Rust + libc FFI で Swift 不要を志向。当面は cache-warden 内 workspace member (= `crates/macos-process-inspect/`)、安定したら別 repo 化。

## 背景

cache-warden の以下用途で **共通基盤**として必要:

- 別 issue: kv get の peer-identity guard (= set 時に「同 SHELL / 同ユーザ / 同祖先 / 特定 codesign / コマンド名」等の constraint を declarative に付与、get 時に peer 情報で評価)
- 別 issue: cw 独自 TouchID dialog (= 1Password の白紙委任 dialog を超え、誰が何を要求してるかをコマンド/引数/プロセスツリーで詳細表示)

両用途で共通する "socket 越しに来た要求の peer identity を信頼できる範囲で多面取得" を 1 crate に集約。

## 想定 API スコープ

- **PID + 祖先プロセスチェーン遡上** (任意段、wrap-safe)
- **macOS unique process identifier** (= `proc_uniqueid` / audit_token persistent ID。PID と違って wrap しない長期 unique 値)
- **UNIX socket peer 特定** (`LOCAL_PEERPID` / `LOCAL_PEEREPID` / `LOCAL_PEERTOKEN`、Apple 固有 socket option)
- **codesign signature 検証** (対抗プロセスの code signature 取得、SecCodeCopyGuestWithAttributes + audit token)
- **env 取得** (peer の env vars、可能な範囲)
- **コマンドラインと argv 取得** (`proc_pidpath` + KERN_PROCARGS2)
- **TCC info 取得** (audit token → identity 引き)
- **enclosing .app bundle 検出** (任意 process path → .app 抽出)

## 設計原則

- Pure Rust + `libc` FFI、Swift / ObjC 不要
- macOS only、non-macOS は no-op shim
- データ取得 API を中心に、policy 評価は利用側責務 (= guard 評価ロジックは crate に持たない)
- feature flag で framework 依存を分離 (`codesign` → Security framework 等)

## permission-flow との関係

veecore/permission-flow には `suggested_host_app_path` (= 親プロセス遡上で .app 推定) があるが、Swift backend 含む大物。当 crate は **Pure Rust** で同等機能を提供 + より多面 (codesign / unique id / peer socket) 提供。

## 関連

- 別 issue: `macos-tcc` crate (= TCC permission check 専用、これと相補的、両 crate で macOS dogfood 系の基盤を形成)
- 元発想: 2026-06-22 セッション、DR-0022 検証完了後の crate 化議論

## 受け入れ条件

- [ ] `crates/macos-process-inspect/` として workspace member 追加
- [ ] PID + 祖先チェーン遡上 API 実装
- [ ] UNIX socket peer 特定 (`LOCAL_PEERPID` / `LOCAL_PEERTOKEN`) 実装
- [ ] macOS unique process identifier (proc_uniqueid) 取得 実装
- [ ] non-macOS no-op shim で cargo test がパスする
