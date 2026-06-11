# secret reference injection (`cache-warden://KEY` 置換)

- Status: wip
- Date: 2026-06-11

## 構想

`cache-warden://KEY` 参照を reveal 値に置換する機能。op run / op inject 相当。

- **`cache-warden run -- cmd`**: env や引数中の `cache-warden://KEY` 参照を解決し、reveal 値を
  env 注入して子コマンドを実行（op run 相当）。CLI 再構成でトップレベル `run` が空いたので、その動詞を充てる。
- **`cache-warden inject`**: 設定ファイル / テンプレ中の `cache-warden://KEY` 参照を reveal 値に
  置換して出力（op inject 相当）。

## 位置づけ

- control socket クライアントとして実装できる（既存 `kv get` と同じ経路）。コアと並列に進められる
  （アダプタ移植や authsock 着手をブロックしない）。
- 秘密値はプロセス内で解決し、子プロセスへの env 注入時のみ外に出る（注入経路の安全性は設計時に詰める）。

## TODO

- [x] 設計（参照構文 / 解決経路 / env 注入の安全性 / `run` と `inject` の責務分担）→ [DR-0013](../decisions/DR-0013-secret-reference-injection.md) で確定
- [x] 事前定義経路の設計（`kv define` / `--defs FILE` / 定義永続化）→ [DR-0014](../decisions/DR-0014-kv-definition-model.md) で確定
- [x] DR-0014 の実装 (1/2): define 動詞 / 定義レジストリ / config lazy 化（v0.9.0）
- [x] DR-0014 の実装 (2/2): `--defs` ファイル / 定義永続化（v0.10.0）
- [ ] 実装（共有 `refs` モジュール / `run` / `inject`、help・補完更新含む）

## 関連

- [docs/decisions/DR-0013-secret-reference-injection.md](../decisions/DR-0013-secret-reference-injection.md) — 設計の確定 DR
- [docs/DESIGN-ja.md](../DESIGN-ja.md) 「将来検討」節（トップレベル `run` の op run 用途）
- CLI 再構成（`run` → `daemon run` 移動、2026-06-11）でトップレベル `run` を空けた
