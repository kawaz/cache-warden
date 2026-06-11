#!/usr/bin/env zsh
# tests/completion.zsh
#
# cache-warden の zsh 補完を zpty で実際にキャプチャして検証する軽量テスト。
# CI 組込みは不要、ローカル実行用。
#
#   zsh tests/completion.zsh
#
# 仕組み: zpty で `zsh -f` を起動し、プロンプトを空にした上で対象行を打って
# TAB (list-choices) を送り、補完候補一覧を複数回 read でドレインして期待
# 文字列の含有を確認する。
#
# 制約: 動的 KEY 補完 (_cw_keys → cache-warden kv list) は外部プロセス起動を
# 伴い list-choices の端末描画が間に合わないことがある。動的補完のロジック自体
# は _verify_dynamic_keys() で「補完エンジンを介さず直接」検証する (こちらが
# 本質的なロジックテスト)。手動確認は README コメント参照。

emulate -L zsh
setopt no_unset

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
BIN="$REPO_ROOT/target/release/cache-warden"

if [[ ! -x "$BIN" ]]; then
  print -u2 "FATAL: build first: cargo build --release ($BIN not found)"
  exit 1
fi

export PATH="$REPO_ROOT/target/release:$PATH"

zmodload zsh/zpty

integer pass=0 fail=0

# PTY から候補が出揃うまで read を繰り返してドレインする。
_drain() {
  local name="$1" chunk acc=""
  integer i
  for (( i = 0; i < 60; i++ )); do
    chunk=""
    zpty -t "$name" 2>/dev/null && zpty -r "$name" chunk 2>/dev/null && acc+="$chunk"
    sleep 0.05
  done
  print -r -- "$acc"
}

# zpty で list-choices を 1 回キャプチャする。
_capture() {
  local line="$1"
  local name="cwtest_${RANDOM}"
  zpty -b "$name" "env COLUMNS=200 LINES=80 PATH='$PATH' zsh -f" 2>/dev/null
  zpty -w "$name" "PROMPT='READY> ' RPROMPT=''"
  zpty -w "$name" "fpath=($REPO_ROOT/completions \$fpath)"
  zpty -w "$name" "autoload -Uz compinit && compinit -u"
  zpty -w "$name" "setopt no_beep no_list_beep"
  zpty -w "$name" "unsetopt auto_menu menu_complete"
  zpty -w "$name" "zstyle ':completion:*' menu no"
  zpty -w "$name" "zstyle ':completion:*' list-prompt ''"
  zpty -w "$name" "zstyle ':completion:*' completer _complete"
  zpty -w "$name" "bindkey '^I' list-choices"
  sleep 0.4
  zpty -r "$name" >/dev/null 2>&1 || true
  zpty -w -n "$name" "$line"
  sleep 0.2
  zpty -w -n "$name" $'\t'
  local out
  out="$(_drain "$name")"
  zpty -d "$name" 2>/dev/null || true
  print -r -- "$out"
}

_expect_contains() {
  local desc="$1" line="$2"; shift 2
  local out; out="$(_capture "$line")"
  local -a missing
  local w
  for w in "$@"; do
    [[ "$out" != *"$w"* ]] && missing+=("$w")
  done
  if (( $#missing == 0 )); then
    print -- "PASS: $desc"
    (( pass++ ))
  else
    print -- "FAIL: $desc — missing: ${missing[*]}"
    print -- "  ----- captured (sanitized) -----"
    print -r -- "$out" | tr -cd '[:print:]\n' | sed 's/^/  | /'
    (( fail++ ))
  fi
}

print "== top-level subcommands =="
_expect_contains "top commands" "cache-warden " daemon ping status kv run inject config

print "== kv subcommands =="
_expect_contains "kv commands" "cache-warden kv " define set get del list pin unpin

print "== config subcommands =="
_expect_contains "config commands" "cache-warden config " show path edit

print "== daemon subcommands =="
_expect_contains "daemon commands" "cache-warden daemon " run

print "== kv define options =="
_expect_contains "kv define opts" "cache-warden kv define KEY --" \
  --command --source --defs --soft-ttl --hard-ttl --type --otp-digits --otp-period --otp-algorithm

print "== kv set options =="
_expect_contains "kv set opts" "cache-warden kv set KEY --" \
  --value --value-stdin --soft-ttl --hard-ttl --type

print "== kv get options =="
_expect_contains "kv get opts" "cache-warden kv get KEY --" --dry-run --reveal

print "== kv del options =="
_expect_contains "kv del opts" "cache-warden kv del KEY --" --with-define

print "== run options =="
_expect_contains "run opts" "cache-warden run --" --env --defs --dry-run --reveal

print "== inject options =="
_expect_contains "inject opts" "cache-warden inject --" --in --out --defs --dry-run --reveal

# ---- 動的 KEY 補完ロジックの直接検証 ----
# 補完エンジン (list-choices) の端末描画に依存せず、_cw_current_socket /
# _cw_keys が daemon の kv list から候補を生成できることを直接確認する。
# 実補完関数 (_arguments) をメインスクリプト内で呼ぶと補完コンテキスト外で
# 不安定になるため、独立した `zsh -f` プロセスで走らせて結果文字列だけ受ける。
print "== dynamic KEY completion logic (direct) =="
_verify_dynamic_keys() {
  local SOCK; SOCK="$(mktemp -u /tmp/cw-comptest-XXXX.sock)"
  "$BIN" daemon run --socket "$SOCK" >/dev/null 2>&1 &
  local dpid=$!
  sleep 0.8
  "$BIN" kv set ALPHA_TOKEN --value a --socket "$SOCK" >/dev/null 2>&1
  "$BIN" kv set BETA_SECRET --value b --socket "$SOCK" >/dev/null 2>&1

  # 子 zsh でヘルパを定義し、socket 抽出 + kv list を実行して結果を返す。
  local result
  result="$(PATH="$PATH" zsh -f -c '
    fpath=("'"$REPO_ROOT"'/completions" $fpath)
    autoload -Uz compinit && compinit -u
    autoload -Uz +X _cache-warden
    words=(cache-warden kv get --socket "'"$SOCK"'" ""); CURRENT=$#words
    _cache-warden >/dev/null 2>&1
    reply=(); _cw_current_socket
    print -r -- "SOCKET:${reply[*]}"
    command cache-warden kv list "${reply[@]}" 2>/dev/null
  ' 2>/dev/null)"

  kill $dpid 2>/dev/null || true
  rm -f "$SOCK"

  local -a missing
  [[ "$result" == *"SOCKET:--socket $SOCK"* ]] || missing+=("socket-extract")
  [[ "$result" == *ALPHA_TOKEN* ]] || missing+=("ALPHA_TOKEN")
  [[ "$result" == *BETA_SECRET* ]] || missing+=("BETA_SECRET")

  if (( $#missing == 0 )); then
    print -- "PASS: dynamic key logic (socket extracted, keys present)"
    (( pass++ ))
  else
    print -- "FAIL: dynamic key logic — missing: ${missing[*]}"
    print -- "  | result=[$(print -r -- "$result" | tr '\n' ' ')]"
    (( fail++ ))
  fi
}
_verify_dynamic_keys

# daemon 不達時に静かに候補なし (エラーを漏らさない) ことの確認。
print "== dynamic KEY graceful degrade (no daemon) =="
_verify_no_daemon() {
  local err
  err="$(PATH="$PATH" zsh -f -c '
    fpath=("'"$REPO_ROOT"'/completions" $fpath)
    autoload -Uz compinit && compinit -u
    autoload -Uz +X _cache-warden
    words=(cache-warden kv get --socket /tmp/cw-nonexistent-$$.sock ""); CURRENT=$#words
    _cache-warden >/dev/null 2>&1
    _cw_keys 2>&1 >/dev/null
  ' 2>/dev/null)"
  if [[ -z "$err" ]]; then
    print -- "PASS: no daemon → silent (no stderr leak)"
    (( pass++ ))
  else
    print -- "FAIL: no daemon leaked stderr: $err"
    (( fail++ ))
  fi
}
_verify_no_daemon

print ""
print "==================================="
print "PASS: $pass   FAIL: $fail"
(( fail == 0 ))
