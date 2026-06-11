# OTP 値型の実装（seed キャッシュ + コード導出）

- Status: open
- Date: 2026-06-11

## 構想

`--type otp` で seed をキャッシュし、`kv get` / 参照解決で 6 桁コードを導出して返す。
seed は write-only（デーモンから出ない）。設計は
[DR-0016](../decisions/DR-0016-otp-value-type.md) で確定済み。

## TODO

- [x] 設計（型メタデータ / 導出のレイヤ / write-only / footgun 排除）→ [DR-0016](../decisions/DR-0016-otp-value-type.md)
- [ ] 実装（`--type otp` + otpauth:// パース + デーモン側 TOTP 導出 + `?attribute=otp` 組合せエラー、RFC テストベクタで TDD）

## 依存

- DR-0014（define / 定義メタデータ）の実装が前提

## 関連

- [docs/decisions/DR-0016-otp-value-type.md](../decisions/DR-0016-otp-value-type.md)
- [docs/decisions/DR-0013-secret-reference-injection.md](../decisions/DR-0013-secret-reference-injection.md) — run / inject（コード注入の経路、実装済み）
